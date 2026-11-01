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

/// Downmixes multi-channel PCM audio to 2-channel stereo.
/// Supported channel configurations:
/// - 1: Mono (duplicated to L and R)
/// - 2: Stereo (direct copy)
/// - 4: Quadraphonic [L, R, Ls, Rs]
/// - 6: 5.1 Surround [L, R, C, LFE, Ls, Rs] (ITU-R BS.775 matrix)
/// - 8: 7.1 Surround [L, R, C, LFE, Ls, Rs, Rls, Rrs]
pub fn downmix_to_stereo(channels: u16, input: &[i16], output: &mut Vec<i16>) {
    if input.is_empty() || channels == 0 {
        return;
    }

    let ch = channels as usize;
    let frames = input.len() / ch;
    output.reserve(frames * 2);

    match channels {
        1 => {
            for &sample in input {
                output.push(sample);
                output.push(sample);
            }
        }
        2 => {
            output.extend_from_slice(input);
        }
        4 => {
            // Quad: L, R, Ls, Rs
            for f in 0..frames {
                let base = f * 4;
                let l = input[base] as f32;
                let r = input[base + 1] as f32;
                let ls = input[base + 2] as f32;
                let rs = input[base + 3] as f32;

                let l_mix = (l + 0.707 * ls).clamp(-32768.0, 32767.0) as i16;
                let r_mix = (r + 0.707 * rs).clamp(-32768.0, 32767.0) as i16;
                output.push(l_mix);
                output.push(r_mix);
            }
        }
        6 => {
            // 5.1 Surround: L, R, C, LFE, Ls, Rs
            for f in 0..frames {
                let base = f * 6;
                let l = input[base] as f32;
                let r = input[base + 1] as f32;
                let c = input[base + 2] as f32;
                let lfe = input[base + 3] as f32;
                let ls = input[base + 4] as f32;
                let rs = input[base + 5] as f32;

                let l_mix = (l + 0.707 * c + 0.707 * ls + 0.5 * lfe).clamp(-32768.0, 32767.0) as i16;
                let r_mix = (r + 0.707 * c + 0.707 * rs + 0.5 * lfe).clamp(-32768.0, 32767.0) as i16;
                output.push(l_mix);
                output.push(r_mix);
            }
        }
        8 => {
            // 7.1 Surround: L, R, C, LFE, Ls, Rs, Rls, Rrs
            for f in 0..frames {
                let base = f * 8;
                let l = input[base] as f32;
                let r = input[base + 1] as f32;
                let c = input[base + 2] as f32;
                let lfe = input[base + 3] as f32;
                let ls = input[base + 4] as f32;
                let rs = input[base + 5] as f32;
                let rls = input[base + 6] as f32;
                let rrs = input[base + 7] as f32;

                let l_mix = (l + 0.707 * c + 0.5 * ls + 0.5 * rls + 0.5 * lfe).clamp(-32768.0, 32767.0) as i16;
                let r_mix = (r + 0.707 * c + 0.5 * rs + 0.5 * rrs + 0.5 * lfe).clamp(-32768.0, 32767.0) as i16;
                output.push(l_mix);
                output.push(r_mix);
            }
        }
        _ => {
            // Generic downmix: average all even channels to L, all odd channels to R
            for f in 0..frames {
                let base = f * ch;
                let mut l_acc = 0.0f32;
                let mut r_acc = 0.0f32;
                let mut l_cnt = 0.0f32;
                let mut r_cnt = 0.0f32;

                for c in 0..ch {
                    let sample = input[base + c] as f32;
                    if c % 2 == 0 {
                        l_acc += sample;
                        l_cnt += 1.0;
                    } else {
                        r_acc += sample;
                        r_cnt += 1.0;
                    }
                }

                let l_mix = (l_acc / l_cnt.max(1.0)).clamp(-32768.0, 32767.0) as i16;
                let r_mix = (r_acc / r_cnt.max(1.0)).clamp(-32768.0, 32767.0) as i16;
                output.push(l_mix);
                output.push(r_mix);
            }
        }
    }
}

/// Deinterleaves multi-channel audio frames into planar per-channel vectors
pub fn deinterleave_planar(interleaved: &[i16], channels: usize, output: &mut [Vec<i16>]) {
    if channels == 0 || output.len() < channels {
        return;
    }
    let frames = interleaved.len() / channels;
    for ch_buf in output.iter_mut().take(channels) {
        ch_buf.clear();
        ch_buf.reserve(frames);
    }
    for f in 0..frames {
        let base = f * channels;
        for c in 0..channels {
            output[c].push(interleaved[base + c]);
        }
    }
}

/// Interleaves planar per-channel audio slices into a single interleaved frame buffer
pub fn interleave_planar(planar: &[&[i16]], output: &mut [i16]) {
    if planar.is_empty() {
        return;
    }
    let channels = planar.len();
    let frames = planar[0].len();
    let expected_len = frames * channels;
    let actual_len = output.len().min(expected_len);
    let valid_frames = actual_len / channels;

    for f in 0..valid_frames {
        let base = f * channels;
        for (c, ch_slice) in planar.iter().enumerate() {
            if f < ch_slice.len() {
                output[base + c] = ch_slice[f];
            }
        }
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

    #[test]
    fn test_downmix_5_1_to_stereo() {
        // 5.1 frame: [L, R, C, LFE, Ls, Rs]
        let input = [1000i16, 2000, 500, 400, 300, 600];
        let mut output = Vec::new();
        downmix_to_stereo(6, &input, &mut output);

        assert_eq!(output.len(), 2);
        // Expected L = 1000 + 0.707*500 + 0.707*300 + 0.5*400 = 1000 + 353.5 + 212.1 + 200 = ~1765
        assert!((output[0] - 1765).abs() <= 2);
        // Expected R = 2000 + 0.707*500 + 0.707*600 + 0.5*400 = 2000 + 353.5 + 424.2 + 200 = ~2977
        assert!((output[1] - 2977).abs() <= 2);
    }

    #[test]
    fn test_planar_interleaving_roundtrip() {
        let ch0 = vec![10i16, 20, 30];
        let ch1 = vec![100i16, 200, 300];
        let ch2 = vec![1000i16, 2000, 3000];

        let mut interleaved = vec![0i16; 9];
        interleave_planar(&[&ch0, &ch1, &ch2], &mut interleaved);
        assert_eq!(interleaved, vec![10, 100, 1000, 20, 200, 2000, 30, 300, 3000]);

        let mut deinterleaved = vec![Vec::new(), Vec::new(), Vec::new()];
        deinterleave_planar(&interleaved, 3, &mut deinterleaved);
        assert_eq!(deinterleaved[0], ch0);
        assert_eq!(deinterleaved[1], ch1);
        assert_eq!(deinterleaved[2], ch2);
    }
}
