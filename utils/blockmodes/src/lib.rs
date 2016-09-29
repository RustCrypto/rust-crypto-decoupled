#![no_std]

// TODO - Optimize the XORs
// TODO - Maybe use macros to specialize BlockEngine for encryption or decryption?
// TODO - I think padding could be done better. Maybe macros for BlockEngine
// would help this too.

extern crate crypto_symmetric;
extern crate crypto_bytes;
extern crate crypto_buffers;

use std::cmp;
use std::iter::repeat;

use buffer::{ReadBuffer, WriteBuffer, BufferResult, RefReadBuffer, RefWriteBuffer,
    OwnedReadBuffer, OwnedWriteBuffer};
use buffer::BufferResult::{BufferUnderflow, BufferOverflow};
use crypto_bytes::copy_memory;
use crypto_symmetric::{BlockEncryptor, BlockEncryptorX8, BlockDecryptor,
    Encryptor, Decryptor, SynchronousStreamCipher, SymmetricCipherError,
    symm_enc_or_dec};
use crypto_symmetric::SymmetricCipherError::{InvalidPadding, InvalidLength};

/// The `BlockProcessor` trait is used to implement modes that require processing
/// complete blocks of data. The methods of this trait are called by the
/// `BlockEngine` which is in charge of properly buffering input data.
trait BlockProcessor {
    /// Process a block of data. The `in_hist` and `out_hist` parameters represent
    /// the input and output when the last block was processed. These values are
    /// necessary for certain modes.
    fn process_block(&mut self, in_hist: &[u8], out_hist: &[u8], input: &[u8],
                     output: &mut [u8]);
}

/// A PaddingProcessor handles adding or removing padding
pub trait PaddingProcessor {
    /// Add padding to the last block of input data. If the mode can't handle
    /// a non-full block, it signals that error by simply leaving the block
    /// as it is which will be detected as an InvalidLength error.
    fn pad_input<W: WriteBuffer>(&mut self, input_buffer: &mut W);

    /// Remove padding from the last block of output data
    /// If false is returned, the processing fails
    fn strip_output<R: ReadBuffer>(&mut self, output_buffer: &mut R) -> bool;
}

/// The `BlockEngine` is implemented as a state machine with the following states.
/// See comments in the `BlockEngine` code for more information on the states.
#[derive(Clone, Copy)]
enum BlockEngineState {
    FastMode,
    NeedInput,
    NeedOutput,
    LastInput,
    LastInput2,
    Finished,
    Error(SymmetricCipherError)
}

/// `BlockEngine` buffers input and output data and handles sending complete
/// block of data to the `Processor` object. Additionally, `BlockEngine` handles
/// logic necessary to add or remove padding by calling the appropriate methods
/// on the `Processor` object.
struct BlockEngine<P, X> {
    /// The block sized expected by the Processor
    block_size: usize,

    /// `in_hist` and `out_hist` keep track of data that was input to and output
    /// from the last invocation of the `process_block()` method of the `Processor`.
    /// Depending on the mode, these may be empty vectors if history is not needed.
    in_hist: Vec<u8>,
    out_hist: Vec<u8>,

    /// If some input data is supplied, but not a complete blocks worth, it is
    /// stored in this buffer until enough arrives that it can be passed to the
    // `process_block()` method of the `Processor`.
    in_scratch: OwnedWriteBuffer,

    /// If input data is processed but there isn't enough space in the output
    /// buffer to store it, it is written into out_write_scratch. `OwnedWriteBuffer`'s
    /// may be converted into `OwnedReaderBuffers` without re-allocating, so,
    /// after being written, out_write_scratch is turned into `out_read_scratch`.
    /// After that, if is written to the output as more output becomes available.
    /// The main point is - only `out_write_scratch` or `out_read_scratch` contains
    ///  a value at any given time; never both.
    out_write_scratch: Option<OwnedWriteBuffer>,
    out_read_scratch: Option<OwnedReadBuffer>,

    /// The processor that implements the particular block mode.
    processor: P,

    /// The padding processor
    padding: X,

    /// The current state of the operation.
    state: BlockEngineState
}

fn update_history(in_hist: &mut [u8], out_hist: &mut [u8], last_in: &[u8], last_out: &[u8]) {
    let in_hist_len = in_hist.len();
    if in_hist_len > 0 {
        copy_memory(
            &last_in[last_in.len() - in_hist_len..],
            in_hist);
    }
    let out_hist_len = out_hist.len();
    if out_hist_len > 0 {
        copy_memory(
            &last_out[last_out.len() - out_hist_len..],
            out_hist);
    }
}

impl <P: BlockProcessor, X: PaddingProcessor> BlockEngine<P, X> {
    /// Create a new `BlockProcessor` instance with the given processor and
    /// `block_size`. No history will be saved.
    fn new(processor: P, padding: X, block_size: usize) -> BlockEngine<P, X> {
        BlockEngine {
            block_size: block_size,
            in_hist: Vec::new(),
            out_hist: Vec::new(),
            in_scratch: OwnedWriteBuffer::new(repeat(0).take(block_size).collect()),
            out_write_scratch: Some(OwnedWriteBuffer::new(repeat(0).take(block_size).collect())),
            out_read_scratch: None,
            processor: processor,
            padding: padding,
            state: BlockEngineState::FastMode
        }
    }

    /// Create a new `BlockProcessor` instance with the given processor, `block_size`,
    /// and initial input and output history.
    fn new_with_history(
            processor: P,
            padding: X,
            block_size: usize,
            in_hist: Vec<u8>,
            out_hist: Vec<u8>) -> BlockEngine<P, X> {
        BlockEngine {
            in_hist: in_hist,
            out_hist: out_hist,
            ..BlockEngine::new(processor, padding, block_size)
        }
    }

    /// This implements the `FastMode` state. Ideally, the encryption or decryption
    /// operation should do the bulk of its work in FastMode. Significantly,
    /// `FastMode` avoids doing copies as much as possible. The `FastMode` state
    /// does not handle the final block of data.
    fn fast_mode<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R,
                                                output: &mut W) -> BlockEngineState {
        fn has_next<R: ReadBuffer, W: WriteBuffer>(input: &mut R, output: &mut W,
                                                   block_size: usize) -> bool {
            // Not the greater than - very important since this method must never
            // process the last block.
            let enough_input = input.remaining() > block_size;
            let enough_output = output.remaining() >= block_size;
            enough_input && enough_output
        };
        fn split_at<'a>(vec: &'a [u8], at: usize) -> (&'a [u8], &'a [u8]) {
            (&vec[..at], &vec[at..])
        }

        // First block processing. We have to retrieve the history information
        // from self.in_hist and self.out_hist.
        if !has_next(input, output, self.block_size) {
            if input.is_empty() {
                return BlockEngineState::FastMode;
            } else {
                return BlockEngineState::NeedInput;
            }
        } else {
            let next_in = input.take_next(self.block_size);
            let next_out = output.take_next(self.block_size);
            self.processor.process_block(
                &self.in_hist[..],
                &self.out_hist[..],
                next_in,
                next_out);
        }

        // Process all remaing blocks. We can pull the history out of the buffers
        // without having to do any copies
        let next_in_size = self.in_hist.len() + self.block_size;
        let next_out_size = self.out_hist.len() + self.block_size;
        while has_next(input, output, self.block_size) {
            input.rewind(self.in_hist.len());
            let (in_hist, next_in) = split_at(input.take_next(next_in_size), self.in_hist.len());
            output.rewind(self.out_hist.len());
            let (out_hist, next_out) = output.take_next(next_out_size).split_at_mut(
                self.out_hist.len());
            self.processor.process_block(
                in_hist,
                out_hist,
                next_in,
                next_out);
        }

        // Save the history and then transition to the next state
        {
            input.rewind(self.in_hist.len());
            let last_in = input.take_next(self.in_hist.len());
            output.rewind(self.out_hist.len());
            let last_out = output.take_next(self.out_hist.len());
            update_history(
                &mut self.in_hist,
                &mut self.out_hist,
                last_in,
                last_out);
        }
        if input.is_empty() {
            BlockEngineState::FastMode
        } else {
            BlockEngineState::NeedInput
        }
    }

    /// This method implements the BlockEngine state machine.
    fn process<R: ReadBuffer, W: WriteBuffer>(&mut self, input: &mut R,
                                        output: &mut W, eof: bool)
                                        -> Result<BufferResult, SymmetricCipherError> {
        // Process a block of data from in_scratch and write the result to
        // out_write_scratch. Finally, convert out_write_scratch into out_read_scratch.
        fn process_scratch<P: BlockProcessor, X: PaddingProcessor>(me: &mut BlockEngine<P, X>) {
            let mut rin = me.in_scratch.take_read_buffer();
            let mut wout = me.out_write_scratch.take().unwrap();

            {
                let next_in = rin.take_remaining();
                let next_out = wout.take_remaining();
                me.processor.process_block(
                    &me.in_hist[..],
                    &me.out_hist[..],
                    next_in,
                    next_out);
                update_history(
                    &mut me.in_hist,
                    &mut me.out_hist,
                    next_in,
                    next_out);
            }

            let rb = wout.into_read_buffer();
            me.out_read_scratch = Some(rb);
        };

        loop {
            match self.state {
                // FastMode tries to process as much data as possible while minimizing copies.
                // FastMode doesn't make use of the scratch buffers and only updates the history
                // just before exiting.
                BlockEngineState::FastMode => {
                    self.state = self.fast_mode(input, output);
                    match self.state {
                        BlockEngineState::FastMode => {
                            // If FastMode completes but stays in the FastMode state, it means that
                            // we've run out of input data.
                            return Ok(BufferUnderflow);
                        }
                        _ => {}
                    }
                }

                // The NeedInput mode is entered when there isn't enough data to run in FastMode
                // anymore. Input data is buffered in in_scratch until there is a full block or eof
                // occurs. IF eof doesn't occur, the data is processed and then we go to the
                // NeedOutput state. Otherwise, we go to the LastInput state. This state always
                // writes all available data into in_scratch before transitioning to the next state.
                BlockEngineState::NeedInput => {
                    input.push_to(&mut self.in_scratch);
                    if !input.is_empty() {
                        // !is_empty() guarantees two things - in_scratch is full and its not the
                        // last block. This state must never process the last block.
                        process_scratch(self);
                        self.state = BlockEngineState::NeedOutput;
                    } else {
                        if eof {
                            self.state = BlockEngineState::LastInput;
                        } else {
                            return Ok(BufferUnderflow);
                        }
                    }
                }

                // The NeedOutput state just writes buffered processed data to the output stream
                // until all of it has been written.
                BlockEngineState::NeedOutput => {
                    let mut rout = self.out_read_scratch.take().unwrap();
                    rout.push_to(output);
                    if rout.is_empty() {
                        self.out_write_scratch = Some(rout.into_write_buffer());
                        self.state = BlockEngineState::FastMode;
                    } else {
                        self.out_read_scratch = Some(rout);
                        return Ok(BufferOverflow);
                    }
                }

                // None of the other states are allowed to process the last block of data since
                // last block handling is a little tricky due to modes have special needs regarding
                // padding. When the last block of data is detected, this state is transitioned to
                // for handling.
                BlockEngineState::LastInput => {
                    // We we arrive in this state, we know that all input data that is going to be
                    // supplied has been suplied and that that data has been written to in_scratch
                    // by the NeedInput state. Furthermore, we know that one of three things must be
                    // true about in_scratch:
                    // 1) It is empty. This only occurs if the input is zero length. We can do last
                    //    block processing by executing the pad_input() method of the processor
                    //    which may either pad out to a full block or leave it empty, process the
                    //    data if it was padded out to a full block, and then pass it to
                    //    strip_output().
                    // 2) It is partially filled. This will occur if the input data was not a
                    //    multiple of the block size. Processing proceeds identically to case #1.
                    // 3) It is full. This case occurs when the input data was a multiple of the
                    //    block size. This case is a little trickier, since, depending on the mode,
                    //    we might actually have 2 blocks worth of data to process - the last user
                    //    supplied block (currently in in_scratch) and then another block that could
                    //    be added as padding. Processing proceeds by first processing the data in
                    //    in_scratch and writing it to out_scratch. Then, the now-empty in_scratch
                    //    buffer is passed to pad_input() which may leave it empty or write a block
                    //    of padding to it. If no padding is added, processing proceeds as in cases
                    //    #1 and #2. However, if padding is added, now have data in in_scratch and
                    //    also in out_scratch meaning that we can't immediately process the padding
                    //    data since we have nowhere to put it. So, we transition to the LastInput2
                    //    state which will first write out the last non-padding block, then process
                    //    the padding block (in in_scratch) and write it to the now-empty
                    //    out_scratch.
                    if !self.in_scratch.is_full() {
                        self.padding.pad_input(&mut self.in_scratch);
                        if self.in_scratch.is_full() {
                            process_scratch(self);
                            if self.padding.strip_output(self.out_read_scratch.as_mut().unwrap()) {
                                self.state = BlockEngineState::Finished;
                            } else {
                                self.state = BlockEngineState::Error(InvalidPadding);
                            }
                        } else if self.in_scratch.is_empty() {
                            self.state = BlockEngineState::Finished;
                        } else {
                            self.state = BlockEngineState::Error(InvalidLength);
                        }
                    } else {
                        process_scratch(self);
                        self.padding.pad_input(&mut self.in_scratch);
                        if self.in_scratch.is_full() {
                            self.state = BlockEngineState::LastInput2;
                        } else if self.in_scratch.is_empty() {
                            if self.padding.strip_output(self.out_read_scratch.as_mut().unwrap()) {
                                self.state = BlockEngineState::Finished;
                            } else {
                                self.state = BlockEngineState::Error(InvalidPadding);
                            }
                        } else {
                            self.state = BlockEngineState::Error(InvalidLength);
                        }
                    }
                }

                // See the comments on LastInput for more details. This state handles final blocks
                // of data in the case that the input was a multiple of the block size and the mode
                // decided to add a full extra block of padding.
                BlockEngineState::LastInput2 => {
                    let mut rout = self.out_read_scratch.take().unwrap();
                    rout.push_to(output);
                    if rout.is_empty() {
                        self.out_write_scratch = Some(rout.into_write_buffer());
                        process_scratch(self);
                        if self.padding.strip_output(self.out_read_scratch.as_mut().unwrap()) {
                            self.state = BlockEngineState::Finished;
                        } else {
                            self.state = BlockEngineState::Error(InvalidPadding);
                        }
                    } else {
                        self.out_read_scratch = Some(rout);
                        return Ok(BufferOverflow);
                    }
                }

                // The Finished mode just writes the data in out_scratch to the output until there
                // is no more data left.
                BlockEngineState::Finished => {
                    match self.out_read_scratch {
                        Some(ref mut rout) => {
                            rout.push_to(output);
                            if rout.is_empty() {
                                return Ok(BufferUnderflow);
                            } else {
                                return Ok(BufferOverflow);
                            }
                        }
                        None => { return Ok(BufferUnderflow); }
                    }
                }

                // The Error state is used to store error information.
                BlockEngineState::Error(err) => {
                    return Err(err);
                }
            }
        }
    }
    fn reset(&mut self) {
        self.state = BlockEngineState::FastMode;
        self.in_scratch.reset();
        if self.out_read_scratch.is_some() {
            let ors = self.out_read_scratch.take().unwrap();
            let ows = ors.into_write_buffer();
            self.out_write_scratch = Some(ows);
        } else {
            self.out_write_scratch.as_mut().unwrap().reset();
        }
    }
    fn reset_with_history(&mut self, in_hist: &[u8], out_hist: &[u8]) {
        self.reset();
        copy_memory(in_hist, &mut self.in_hist);
        copy_memory(out_hist, &mut self.out_hist);
    }
}

/// No padding mode for ECB and CBC encryption
#[derive(Clone, Copy)]
pub struct NoPadding;

impl PaddingProcessor for NoPadding {
    fn pad_input<W: WriteBuffer>(&mut self, _: &mut W) { }
    fn strip_output<R: ReadBuffer>(&mut self, _: &mut R) -> bool { true }
}

/// PKCS padding mode for ECB and CBC encryption
#[derive(Clone, Copy)]
pub struct PkcsPadding;

// This class implements both encryption padding, where padding is added, and decryption padding,
// where padding is stripped. Since BlockEngine doesn't know if its an Encryption or Decryption
// operation, it will call both methods if given a chance. So, this class can't be passed directly
// to BlockEngine. Instead, it must be wrapped with EncPadding or DecPadding which will ensure that
// only the propper methods are called. The client of the library, however, doesn't have to
// distinguish encryption padding handling from decryption padding handline, which is the whole
// point.
impl PaddingProcessor for PkcsPadding {
    fn pad_input<W: WriteBuffer>(&mut self, input_buffer: &mut W) {
        let rem = input_buffer.remaining();
        assert!(rem != 0 && rem <= 255);
        for v in input_buffer.take_remaining().iter_mut() {
            *v = rem as u8;
        }
    }
    fn strip_output<R: ReadBuffer>(&mut self, output_buffer: &mut R) -> bool {
        let last_byte: u8;
        {
            let data = output_buffer.peek_remaining();
            last_byte = *data.last().unwrap();
            for &x in data.iter().rev().take(last_byte as usize) {
                if x != last_byte {
                    return false;
                }
            }
        }
        output_buffer.truncate(last_byte as usize);
        true
    }
}

/// Wraps a PaddingProcessor so that only pad_input() will actually be called.
pub struct EncPadding<X> {
    padding: X
}

impl <X: PaddingProcessor> EncPadding<X> {
    fn wrap(p: X) -> EncPadding<X> { EncPadding { padding: p } }
}

impl <X: PaddingProcessor> PaddingProcessor for EncPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, a: &mut W) { self.padding.pad_input(a); }
    fn strip_output<R: ReadBuffer>(&mut self, _: &mut R) -> bool { true }
}

/// Wraps a PaddingProcessor so that only strip_output() will actually be called.
pub struct DecPadding<X> {
    padding: X
}

impl <X: PaddingProcessor> DecPadding<X> {
    fn wrap(p: X) -> DecPadding<X> { DecPadding { padding: p } }
}

impl <X: PaddingProcessor> PaddingProcessor for DecPadding<X> {
    fn pad_input<W: WriteBuffer>(&mut self, _: &mut W) { }
    fn strip_output<R: ReadBuffer>(&mut self, a: &mut R) -> bool { self.padding.strip_output(a) }
}

struct EcbEncryptorProcessor<T> {
    algo: T
}

impl <T: BlockEncryptor> BlockProcessor for EcbEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.encrypt_block(input, output);
    }
}

/// ECB Encryption mode
pub struct EcbEncryptor<T, X> {
    block_engine: BlockEngine<EcbEncryptorProcessor<T>, X>
}

impl <T: BlockEncryptor, X: PaddingProcessor> EcbEncryptor<T, X> {
    /// Create a new ECB encryption mode object
    pub fn new(algo: T, padding: X) -> EcbEncryptor<T, EncPadding<X>> {
        let block_size = algo.block_size();
        let processor = EcbEncryptorProcessor {
            algo: algo
        };
        EcbEncryptor {
            block_engine: BlockEngine::new(processor, EncPadding::wrap(padding), block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockEncryptor, X: PaddingProcessor> Encryptor for EcbEncryptor<T, X> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct EcbDecryptorProcessor<T> {
    algo: T
}

impl <T: BlockDecryptor> BlockProcessor for EcbDecryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, output);
    }
}

/// ECB Decryption mode
pub struct EcbDecryptor<T, X> {
    block_engine: BlockEngine<EcbDecryptorProcessor<T>, X>
}

impl <T: BlockDecryptor, X: PaddingProcessor> EcbDecryptor<T, X> {
    /// Create a new ECB decryption mode object
    pub fn new(algo: T, padding: X) -> EcbDecryptor<T, DecPadding<X>> {
        let block_size = algo.block_size();
        let processor = EcbDecryptorProcessor {
            algo: algo
        };
        EcbDecryptor {
            block_engine: BlockEngine::new(processor, DecPadding::wrap(padding), block_size)
        }
    }
    pub fn reset(&mut self) {
        self.block_engine.reset();
    }
}

impl <T: BlockDecryptor, X: PaddingProcessor> Decryptor for EcbDecryptor<T, X> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcEncryptorProcessor<T> {
    algo: T,
    temp: Vec<u8>
}

impl <T: BlockEncryptor> BlockProcessor for CbcEncryptorProcessor<T> {
    fn process_block(&mut self, _: &[u8], out_hist: &[u8], input: &[u8], output: &mut [u8]) {
        for ((&x, &y), o) in input.iter().zip(out_hist.iter()).zip(self.temp.iter_mut()) {
            *o = x ^ y;
        }
        self.algo.encrypt_block(&self.temp[..], output);
    }
}

/// CBC encryption mode
pub struct CbcEncryptor<T, X> {
    block_engine: BlockEngine<CbcEncryptorProcessor<T>, X>
}

impl <T: BlockEncryptor, X: PaddingProcessor> CbcEncryptor<T, X> {
    /// Create a new CBC encryption mode object
    pub fn new(algo: T, padding: X, iv: Vec<u8>) -> CbcEncryptor<T, EncPadding<X>> {
        let block_size = algo.block_size();
        let processor = CbcEncryptorProcessor {
            algo: algo,
            temp: repeat(0).take(block_size).collect()
        };
        CbcEncryptor {
            block_engine: BlockEngine::new_with_history(
                processor,
                EncPadding::wrap(padding),
                block_size,
                Vec::new(),
                iv)
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(&[], iv);
    }
}

impl <T: BlockEncryptor, X: PaddingProcessor> Encryptor for CbcEncryptor<T, X> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

struct CbcDecryptorProcessor<T> {
    algo: T,
    temp: Vec<u8>
}

impl <T: BlockDecryptor> BlockProcessor for CbcDecryptorProcessor<T> {
    fn process_block(&mut self, in_hist: &[u8], _: &[u8], input: &[u8], output: &mut [u8]) {
        self.algo.decrypt_block(input, &mut self.temp);
        for ((&x, &y), o) in self.temp.iter().zip(in_hist.iter()).zip(output.iter_mut()) {
            *o = x ^ y;
        }
    }
}

/// CBC decryption mode
pub struct CbcDecryptor<T, X> {
    block_engine: BlockEngine<CbcDecryptorProcessor<T>, X>
}

impl <T: BlockDecryptor, X: PaddingProcessor> CbcDecryptor<T, X> {
    /// Create a new CBC decryption mode object
    pub fn new(algo: T, padding: X, iv: Vec<u8>) -> CbcDecryptor<T, DecPadding<X>> {
        let block_size = algo.block_size();
        let processor = CbcDecryptorProcessor {
            algo: algo,
            temp: repeat(0).take(block_size).collect()
        };
        CbcDecryptor {
            block_engine: BlockEngine::new_with_history(
                processor,
                DecPadding::wrap(padding),
                block_size,
                iv,
                Vec::new())
        }
    }
    pub fn reset(&mut self, iv: &[u8]) {
        self.block_engine.reset_with_history(iv, &[]);
    }
}

impl <T: BlockDecryptor, X: PaddingProcessor> Decryptor for CbcDecryptor<T, X> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, eof: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        self.block_engine.process(input, output, eof)
    }
}

fn add_ctr(ctr: &mut [u8], mut ammount: u8) {
    for i in ctr.iter_mut().rev() {
        let prev = *i;
        *i = i.wrapping_add(ammount);
        if *i >= prev {
            break;
        }
        ammount = 1;
    }
}

/// CTR Mode
pub struct CtrMode<A> {
    algo: A,
    ctr: Vec<u8>,
    bytes: OwnedReadBuffer
}

impl <A: BlockEncryptor> CtrMode<A> {
    /// Create a new CTR object
    pub fn new(algo: A, ctr: Vec<u8>) -> CtrMode<A> {
        let block_size = algo.block_size();
        CtrMode {
            algo: algo,
            ctr: ctr,
            bytes: OwnedReadBuffer::new_with_len(repeat(0).take(block_size).collect(), 0)
        }
    }
    pub fn reset(&mut self, ctr: &[u8]) {
        copy_memory(ctr, &mut self.ctr);
        self.bytes.reset();
    }
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0;
        while i < len {
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block(&self.ctr[..], wb.take_remaining());
                add_ctr(&mut self.ctr, 1);
            }
            let count = cmp::min(self.bytes.remaining(), len - i);
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input[i..].iter();
            let out_it = output[i..].iter_mut();
            for ((&x, &y), o) in bytes_it.zip(in_it).zip(out_it) {
                *o = x ^ y;
            }
            i += count;
        }
    }
}

impl <A: BlockEncryptor> SynchronousStreamCipher for CtrMode<A> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output);
    }
}

impl <A: BlockEncryptor> Encryptor for CtrMode<A> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl <A: BlockEncryptor> Decryptor for CtrMode<A> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

/// CTR Mode that operates on 8 blocks at a time
pub struct CtrModeX8<A> {
    algo: A,
    ctr_x8: Vec<u8>,
    bytes: OwnedReadBuffer
}

fn construct_ctr_x8(in_ctr: &[u8], out_ctr_x8: &mut [u8]) {
    for (i, ctr_i) in out_ctr_x8.chunks_mut(in_ctr.len()).enumerate() {
        copy_memory(in_ctr, ctr_i);
        add_ctr(ctr_i, i as u8);
    }
}

impl <A: BlockEncryptorX8> CtrModeX8<A> {
    /// Create a new CTR object that operates on 8 blocks at a time
    pub fn new(algo: A, ctr: &[u8]) -> CtrModeX8<A> {
        let block_size = algo.block_size();
        let mut ctr_x8: Vec<u8> = repeat(0).take(block_size * 8).collect();
        construct_ctr_x8(ctr, &mut ctr_x8);
        CtrModeX8 {
            algo: algo,
            ctr_x8: ctr_x8,
            bytes: OwnedReadBuffer::new_with_len(repeat(0).take(block_size * 8).collect(), 0)
        }
    }
    pub fn reset(&mut self, ctr: &[u8]) {
        construct_ctr_x8(ctr, &mut self.ctr_x8);
        self.bytes.reset();
    }
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        // TODO - Can some of this be combined with regular CtrMode?
        assert!(input.len() == output.len());
        let len = input.len();
        let mut i = 0;
        while i < len {
            if self.bytes.is_empty() {
                let mut wb = self.bytes.borrow_write_buffer();
                self.algo.encrypt_block_x8(&self.ctr_x8[..], wb.take_remaining());
                for ctr_i in &mut self.ctr_x8.chunks_mut(self.algo.block_size()) {
                    add_ctr(ctr_i, 8);
                }
            }
            let count = cmp::min(self.bytes.remaining(), len - i);
            let bytes_it = self.bytes.take_next(count).iter();
            let in_it = input[i..].iter();
            let out_it = &mut output[i..];
            for ((&x, &y), o) in bytes_it.zip(in_it).zip(out_it.iter_mut()) {
                *o = x ^ y;
            }
            i += count;
        }
    }
}

impl <A: BlockEncryptorX8> SynchronousStreamCipher for CtrModeX8<A> {
    fn process(&mut self, input: &[u8], output: &mut [u8]) {
        self.process(input, output);
    }
}

impl <A: BlockEncryptorX8> Encryptor for CtrModeX8<A> {
    fn encrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

impl <A: BlockEncryptorX8> Decryptor for CtrModeX8<A> {
    fn decrypt(&mut self, input: &mut RefReadBuffer, output: &mut RefWriteBuffer, _: bool)
            -> Result<BufferResult, SymmetricCipherError> {
        symm_enc_or_dec(self, input, output)
    }
}

// #[cfg(test)]
// mod tests;

// #[cfg(test)]
// mod bench;
