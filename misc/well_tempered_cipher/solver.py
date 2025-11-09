"""
Solver for Bach B-flat Audio Steganography Challenge
Based on hints about notes, tuning, and Bach forms

Claude Sonnet 4.5 used to add code comments
"""

import numpy as np
from scipy.io import wavfile
import itertools

class BachSolver:
    def __init__(self):
        # Hint 2: "clarinets, trumpets, and saxophones all agree on when they tune up"
        # Wind instruments tune to B-flat!
        self.bb_frequencies = [
            233.08,  # Bb3
            466.16,  # Bb4 (concert pitch tuning note)
            932.33,  # Bb5
        ]
        
        # Hint 3: "Bach forms open doors" - try Bach musical forms as passwords
        self.bach_passwords = [
            "fugue",
            "prelude",
            "toccata",
            "partita",
            "invention",
            "sonata",
            "suite",
            "concerto",
            "cantata",
            "mass",
            "passacaglia",
            "chaconne",
            "fantasy",
            "chorale",
            "counterpoint",
            "",  # Try no password too
        ]
    
    def detect_frequency_peaks(self, audio_file, target_freq, threshold=0.3, min_distance=0.2):
        """
        Detect occurrences of a specific frequency in audio
        Hint 1: "Not all notes are created equal" - we need a SPECIFIC note
        """
        sample_rate, audio_data = wavfile.read(audio_file)
        
        # Convert to mono if stereo
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
        
        # Normalize
        audio_data = audio_data.astype(float) / np.max(np.abs(audio_data))
        
        window_size = 4096
        hop_size = 512
        timestamps = []
        
        print(f"[*] Scanning for {target_freq:.2f} Hz...")
        
        # Sliding window FFT analysis
        for i in range(0, len(audio_data) - window_size, hop_size):
            window = audio_data[i:i + window_size] * np.hanning(window_size)
            
            fft = np.fft.rfft(window)
            freqs = np.fft.rfftfreq(window_size, 1/sample_rate)
            magnitudes = np.abs(fft)
            
            # Find the frequency bin closest to target
            target_idx = np.argmin(np.abs(freqs - target_freq))
            
            # Check if this frequency is prominent
            if magnitudes[target_idx] > threshold * np.max(magnitudes):
                timestamp = i / sample_rate
                
                # Avoid duplicate detections
                if not timestamps or timestamp - timestamps[-1] > min_distance:
                    timestamps.append(timestamp)
        
        return timestamps, sample_rate
    
    def extract_bits_from_positions(self, audio_file, timestamps, sample_rate):
        """
        Extract LSB from specific timestamp positions
        """
        _, audio_data = wavfile.read(audio_file)
        
        if len(audio_data.shape) > 1:
            audio_data = audio_data.mean(axis=1)
        
        bits = []
        for timestamp in timestamps:
            sample_idx = int(timestamp * sample_rate)
            if sample_idx < len(audio_data):
                sample_val = int(audio_data[sample_idx])
                bit = sample_val & 1  # Extract LSB
                bits.append(str(bit))
        
        return ''.join(bits)
    
    def decode_message(self, bit_string, password=None):
        """
        Decode bit string to message with optional XOR decryption
        """
        try:
            # Read length header (first 32 bits)
            if len(bit_string) < 32:
                return None
            
            length_bits = bit_string[:32]
            message_length = int(length_bits, 2)
            
            # Sanity check
            if message_length > 1000 or message_length <= 0:
                return None
            
            # Extract message bits
            message_bits = bit_string[32:32 + message_length * 8]
            
            if len(message_bits) < message_length * 8:
                return None
            
            # Convert to bytes
            message_bytes = bytearray()
            for i in range(0, len(message_bits), 8):
                byte = int(message_bits[i:i+8], 2)
                message_bytes.append(byte)
            
            # Decode
            message = message_bytes.decode('utf-8', errors='ignore')
            
            # Decrypt with password if provided
            if password:
                message = ''.join(chr(ord(c) ^ ord(password[i % len(password)])) 
                                for i, c in enumerate(message))
            
            # Check if it looks like a flag
            if 'csaw{' in message or 'flag{' in message or 'CTF{' in message:
                return message
            
            # Return if it's printable ASCII
            if all(32 <= ord(c) <= 126 for c in message):
                return message
            
            return None
            
        except Exception as e:
            return None
    
    def solve(self, audio_file):
        """
        Main solver - tries different frequencies and passwords
        """
        print("=" * 60)
        print("BACH STEGANOGRAPHY SOLVER")
        print("=" * 60)
        print("\n[*] Analyzing hints...")
        print("    Hint 1: 'Not all notes are created equal' → specific note important")
        print("    Hint 2: 'clarinets, trumpets, saxophones tune up' → B-flat!")
        print("    Hint 3: 'Bach forms open doors' → password is a Bach form")
        
        # Try each B-flat frequency
        for freq in self.bb_frequencies:
            print(f"\n[*] Trying frequency: {freq:.2f} Hz (B-flat)")
            
            timestamps, sample_rate = self.detect_frequency_peaks(audio_file, freq)
            print(f"[+] Found {len(timestamps)} occurrences")
            
            if len(timestamps) < 32:
                print("[-] Not enough data points, skipping...")
                continue
            
            # Extract bits
            bit_string = self.extract_bits_from_positions(audio_file, timestamps, sample_rate)
            print(f"[+] Extracted {len(bit_string)} bits")
            
            # Try each password
            print(f"[*] Trying {len(self.bach_passwords)} Bach-related passwords...")
            
            for password in self.bach_passwords:
                pwd_display = password if password else "(no password)"
                
                message = self.decode_message(bit_string, password if password else None)
                
                if message:
                    # Check if it's a valid flag
                    if 'csaw{' in message or 'flag{' in message or 'CTF{' in message:
                        print("\n" + "=" * 60)
                        print("🎵 FLAG FOUND! 🎵")
                        print("=" * 60)
                        print(f"Frequency: {freq:.2f} Hz")
                        print(f"Password: {pwd_display}")
                        print(f"Flag: {message}")
                        print("=" * 60)
                        return message
                    else:
                        print(f"    [?] Possible message with '{pwd_display}': {message[:50]}...")
        
        print("\n[-] No flag found. Try adjusting detection parameters.")
        return None
    
    def interactive_mode(self, audio_file):
        """
        Interactive mode for manual testing
        """
        print("\n=== INTERACTIVE MODE ===")
        print("Try custom frequencies and passwords\n")
        
        freq = float(input("Enter frequency to detect (Hz) [466.16]: ") or "466.16")
        threshold = float(input("Enter detection threshold [0.3]: ") or "0.3")
        
        timestamps, sample_rate = self.detect_frequency_peaks(
            audio_file, freq, threshold=threshold
        )
        print(f"\n[+] Found {len(timestamps)} occurrences")
        
        if len(timestamps) > 0:
            bit_string = self.extract_bits_from_positions(audio_file, timestamps, sample_rate)
            print(f"[+] Extracted {len(bit_string)} bits")
            
            password = input("\nEnter password (press Enter for none): ")
            message = self.decode_message(bit_string, password if password else None)
            
            if message:
                print(f"\n[+] Decoded message: {message}")
            else:
                print("\n[-] Could not decode message")


if __name__ == "__main__":
    import sys
    
    print("""
    ╔═══════════════════════════════════════════════════════╗
    ║  Bach B-flat Audio Steganography Challenge Solver    ║
    ║  "The Well-Tempered Cipher"                          ║
    ╚═══════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python solver.py <audio_file.wav>")
        print("       python solver.py <audio_file.wav> --interactive")
        sys.exit(1)
    
    audio_file = sys.argv[1]
    solver = BachSolver()
    
    if "--interactive" in sys.argv or "-i" in sys.argv:
        solver.interactive_mode(audio_file)
    else:
        result = solver.solve(audio_file)
        
        if not result:
            print("\n[?] Want to try interactive mode? Run with --interactive flag")