"""
Bach B-flat Audio Steganography Challenge
Embeds data at B-flat note occurrences in audio

Claude Sonnet 4.5 used to add code comments
"""

import numpy as np
import wave
import struct
from scipy import signal
from scipy.io import wavfile
import matplotlib.pyplot as plt

class BachSteganography:
    def __init__(self, bb_frequency=466.16):  # B-flat4 frequency
        self.bb_freq = bb_frequency
        self.tolerance = 10  # Hz tolerance for note detection
        
    def detect_bb_notes(self, audio_file, threshold=0.3, min_distance=0.2):
        """
        Detect B-flat notes in the audio file
        Returns list of timestamps where B-flat occurs
        """
        # Read audio file
        sample_rate, audio_data = wavfile.read(audio_file)
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
        
        # Normalize
        audio_data = audio_data.astype(float) / np.max(np.abs(audio_data))
        
        # Parameters for analysis
        window_size = 4096
        hop_size = 512
        bb_timestamps = []
        
        print(f"Analyzing audio (sample rate: {sample_rate} Hz)...")
        
        # Slide through audio with FFT windows
        for i in range(0, len(audio_data) - window_size, hop_size):
            window = audio_data[i:i + window_size]
            
            # Apply Hanning window
            window = window * np.hanning(window_size)
            
            # Compute FFT
            fft = np.fft.rfft(window)
            freqs = np.fft.rfftfreq(window_size, 1/sample_rate)
            magnitudes = np.abs(fft)
            
            # Find peak around B-flat frequency
            bb_idx = np.argmin(np.abs(freqs - self.bb_freq))
            freq_range = range(max(0, bb_idx - 5), min(len(freqs), bb_idx + 5))
            
            # Check if B-flat is prominent
            if magnitudes[bb_idx] > threshold * np.max(magnitudes):
                timestamp = i / sample_rate
                
                # Avoid duplicates (notes held for duration)
                if not bb_timestamps or timestamp - bb_timestamps[-1] > min_distance:
                    bb_timestamps.append(timestamp)
        
        print(f"Found {len(bb_timestamps)} B-flat occurrences")
        return bb_timestamps, sample_rate
    
    def embed_data(self, audio_file, output_file, message, password=None):
        """
        Embed message at B-flat note positions using LSB modification
        """
        # Detect B-flat positions
        bb_timestamps, sample_rate = self.detect_bb_notes(audio_file)
        
        if len(bb_timestamps) == 0:
            raise ValueError("No B-flat notes detected in audio!")
        
        # Convert message to binary
        if password:
            # Simple XOR cipher with password
            message = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) 
                            for i, c in enumerate(message))
        
        # Add length header and convert to bits
        message_bytes = message.encode('utf-8')
        length_header = len(message_bytes).to_bytes(4, 'big')
        full_data = length_header + message_bytes
        
        bits = ''.join(format(byte, '08b') for byte in full_data)
        
        print(f"Message length: {len(message_bytes)} bytes ({len(bits)} bits)")
        print(f"Available B-flat positions: {len(bb_timestamps)}")
        
        if len(bits) > len(bb_timestamps):
            raise ValueError(f"Message too long! Need {len(bits)} positions, have {len(bb_timestamps)}")
        
        # Read audio
        sample_rate, audio_data = wavfile.read(audio_file)
        original_dtype = audio_data.dtype
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1).astype(original_dtype)
        
        # Embed bits at B-flat positions
        for i, bit in enumerate(bits):
            timestamp = bb_timestamps[i]
            sample_idx = int(timestamp * sample_rate)
            
            if sample_idx < len(audio_data):
                # Modify LSB of sample
                if original_dtype == np.int16:
                    sample_val = int(audio_data[sample_idx])
                    # Clear LSB and set to bit value
                    sample_val = (sample_val & ~1) | int(bit)
                    audio_data[sample_idx] = sample_val
        
        # Save modified audio
        wavfile.write(output_file, sample_rate, audio_data.astype(original_dtype))
        print(f"Data embedded successfully in {output_file}")
        print(f"Used {len(bits)} of {len(bb_timestamps)} available positions")
        
        return len(bits)
    
    def extract_data(self, audio_file, password=None):
        """
        Extract hidden message from B-flat positions
        """
        # Detect B-flat positions
        bb_timestamps, sample_rate = self.detect_bb_notes(audio_file)
        
        if len(bb_timestamps) == 0:
            raise ValueError("No B-flat notes detected!")
        
        # Read audio
        sample_rate, audio_data = wavfile.read(audio_file)
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
        
        # Extract bits from B-flat positions
        bits = []
        for timestamp in bb_timestamps:
            sample_idx = int(timestamp * sample_rate)
            if sample_idx < len(audio_data):
                sample_val = int(audio_data[sample_idx])
                bit = sample_val & 1  # Get LSB
                bits.append(str(bit))
        
        # Convert bits to bytes
        bit_string = ''.join(bits)
        
        # Read length header (first 32 bits)
        if len(bit_string) < 32:
            raise ValueError("Not enough data to read length header")
        
        length_bits = bit_string[:32]
        message_length = int(length_bits, 2)
        
        # Extract message bits
        message_bits = bit_string[32:32 + message_length * 8]
        
        if len(message_bits) < message_length * 8:
            raise ValueError("Incomplete message data")
        
        # Convert to bytes
        message_bytes = bytearray()
        for i in range(0, len(message_bits), 8):
            byte = int(message_bits[i:i+8], 2)
            message_bytes.append(byte)
        
        # Decode message
        message = message_bytes.decode('utf-8', errors='ignore')
        
        # Decrypt if password provided
        if password:
            message = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) 
                            for i, c in enumerate(message))
        
        return message
    
    def visualize_positions(self, audio_file):
        """
        Visualize where B-flat notes occur in the audio
        """
        bb_timestamps, sample_rate = self.detect_bb_notes(audio_file)
        sample_rate, audio_data = wavfile.read(audio_file)
        
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
        
        time_axis = np.arange(len(audio_data)) / sample_rate
        
        plt.figure(figsize=(14, 6))
        plt.plot(time_axis, audio_data, alpha=0.5, linewidth=0.5)
        
        for ts in bb_timestamps:
            plt.axvline(x=ts, color='r', alpha=0.3, linestyle='--')
        
        plt.xlabel('Time (seconds)')
        plt.ylabel('Amplitude')
        plt.title(f'B-flat Note Positions ({len(bb_timestamps)} detected)')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig('bb_positions.png', dpi=150)
        print("Visualization saved to bb_positions.png")


# Example usage
if __name__ == "__main__":
    stego = BachSteganography()
    
    # Example 1: Embed data
    print("=== EMBEDDING DATA ===")
    audio_input = "bach_g_minor.wav"  # Your Bach audio file
    audio_output = "bach_stego.wav"
    secret_message = "flag{b_flat_bach_beethoven_binary}"
    password = "fugue"
    
    try:
        bits_used = stego.embed_data(audio_input, audio_output, secret_message, password)
        print(f"\n✓ Secret embedded in {audio_output}")
    except Exception as e:
        print(f"Error during embedding: {e}")
    
    print("\n=== EXTRACTING DATA ===")
    try:
        extracted = stego.extract_data(audio_output, password)
        print(f"Extracted message: {extracted}")
    except Exception as e:
        print(f"Error during extraction: {e}")
    
    print("\n=== VISUALIZATION ===")
    try:
        stego.visualize_positions(audio_input)
    except Exception as e:
        print(f"Error during visualization: {e}")