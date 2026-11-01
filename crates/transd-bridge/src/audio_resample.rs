/// High-Fidelity Audio Sample Rate Converter for Transd DBT.
/// Handles seamless fractional linear interpolation between guest sample rates
/// (e.g. 44,100 Hz, 22,050 Hz) and host hardware mixer rate (48,000 Hz)
/// with zero phase discontinuity across consecutive buffer chunks.
pub struct AudioResampler {
    pub src_rate: u32,
    pub dst_rate: u32,
    phase: f64,
    last_left: i16,
    last_right: i16,
}

impl AudioResampler {
    pub fn new(src_rate: u32, dst_rate: u32) -> Self {
        Self {
            src_rate: src_rate.max(1),
            dst_rate: dst_rate.max(1),
            phase: 0.0,
            last_left: 0,
            last_right: 0,
        }
    }

    /// Updates sample rates
    pub fn set_rates(&mut self, src_rate: u32, dst_rate: u32) {
        self.src_rate = src_rate.max(1);
        self.dst_rate = dst_rate.max(1);
        self.phase = 0.0;
    }

    /// Resamples interleaved stereo 16-bit PCM from `src_rate` to `dst_rate`.
    /// `input` format: [L0, R0, L1, R1, ...]
    /// Output is appended to `output`.
    pub fn resample_stereo(&mut self, input: &[i16], output: &mut Vec<i16>) {
        if input.is_empty() {
            return;
        }

        // Fast path: identical sample rates -> direct copy
        if self.src_rate == self.dst_rate {
            output.extend_from_slice(input);
            if input.len() >= 2 {
                self.last_left = input[input.len() - 2];
                self.last_right = input[input.len() - 1];
            }
            return;
        }

        let input_frames = input.len() / 2;
        if input_frames == 0 {
            return;
        }

        let step = self.src_rate as f64 / self.dst_rate as f64;
        let estimated_output_frames = ((input_frames as f64 / step) + 2.0) as usize;
        output.reserve(estimated_output_frames * 2);

        while self.phase < (input_frames as f64) {
            let idx = self.phase.floor() as usize;
            let frac = (self.phase - (idx as f64)) as f32;

            let base0 = idx * 2;
            let (l0, r0) = if base0 + 1 < input.len() {
                (input[base0], input[base0 + 1])
            } else {
                (self.last_left, self.last_right)
            };

            let base1 = (idx + 1) * 2;
            let (l1, r1) = if base1 + 1 < input.len() {
                (input[base1], input[base1 + 1])
            } else {
                (l0, r0)
            };

            let l_interp = ((l0 as f32) * (1.0 - frac) + (l1 as f32) * frac) as i16;
            let r_interp = ((r0 as f32) * (1.0 - frac) + (r1 as f32) * frac) as i16;

            output.push(l_interp);
            output.push(r_interp);

            self.phase += step;
        }

        self.phase -= input_frames as f64;
        if input.len() >= 2 {
            self.last_left = input[input.len() - 2];
            self.last_right = input[input.len() - 1];
        }
    }

    /// Converts mono PCM to stereo interleaved PCM, then resamples
    pub fn resample_mono_to_stereo(&mut self, input: &[i16], output: &mut Vec<i16>) {
        if input.is_empty() {
            return;
        }

        let mut stereo_buf = Vec::with_capacity(input.len() * 2);
        for &sample in input {
            stereo_buf.push(sample);
            stereo_buf.push(sample);
        }

        self.resample_stereo(&stereo_buf, output);
    }

    /// Resets resampler phase and previous samples
    pub fn reset(&mut self) {
        self.phase = 0.0;
        self.last_left = 0;
        self.last_right = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resampler_passthrough_at_matching_rate() {
        let mut resampler = AudioResampler::new(48000, 48000);
        let input = [100i16, -100, 200, -200, 300, -300];
        let mut output = Vec::new();
        resampler.resample_stereo(&input, &mut output);

        assert_eq!(output, input);
    }

    #[test]
    fn test_resampler_44100_to_48000() {
        let mut resampler = AudioResampler::new(44100, 48000);
        // 441 frames of stereo audio (882 samples)
        let mut input = Vec::with_capacity(882);
        for i in 0..441 {
            input.push((i * 10) as i16);
            input.push((-i * 10) as i16);
        }

        let mut output = Vec::new();
        resampler.resample_stereo(&input, &mut output);

        // 441 frames * (48000 / 44100) = ~480 frames = ~960 samples
        let out_frames = output.len() / 2;
        assert!((out_frames as i32 - 480).abs() <= 2);
    }

    #[test]
    fn test_resampler_mono_to_stereo() {
        let mut resampler = AudioResampler::new(48000, 48000);
        let input = [500i16, 600, 700];
        let mut output = Vec::new();
        resampler.resample_mono_to_stereo(&input, &mut output);

        assert_eq!(output, vec![500, 500, 600, 600, 700, 700]);
    }
}
