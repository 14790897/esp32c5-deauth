import sys
import threading

import serial

PORT = sys.argv[1] if len(sys.argv) > 1 else "COM12"
BAUD = 115200


def main():
    s = serial.Serial(PORT, BAUD, timeout=0.1, write_timeout=0.5)
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            try:
                data = s.read(4096)
            except Exception:
                break
            if data:
                sys.stdout.write(data.decode(errors="replace"))
                sys.stdout.flush()

    threading.Thread(target=reader, daemon=True).start()
    print(f"\n[{PORT}] c5-deauth console, Ctrl-C to quit\n")
    try:
        s.write(b"\n")
    except Exception:
        pass

    try:
        if sys.platform == "win32":
            import msvcrt

            while True:
                ch = msvcrt.getwch()
                if ch == "\x03":
                    break
                if ch in ("\r", "\n"):
                    s.write(b"\n")
                elif ch == "\x08":
                    s.write(b"\x7f")
                elif ch in ("\x00", "\xe0"):
                    msvcrt.getwch()
                else:
                    try:
                        s.write(ch.encode("ascii"))
                    except UnicodeEncodeError:
                        pass
        else:
            while True:
                line = input()
                s.write((line + "\n").encode())
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        s.close()
        print("\nbye")


if __name__ == "__main__":
    main()
