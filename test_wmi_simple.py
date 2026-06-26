"""
Simple WMI Test - Run this to verify WMI is working on your system
"""
import sys
import time

try:
    import wmi
    import pythoncom
    print("✅ WMI module imported successfully")
except ImportError as e:
    print(f"❌ Failed to import WMI: {e}")
    sys.exit(1)

print("\n🔍 Testing WMI Process Monitor...")
print("Open another terminal and run ANY command (like 'notepad' or 'wevtutil')")
print("You should see it appear below within 1-2 seconds.\n")
print("Press Ctrl+C to stop.\n")
print("="*80)

pythoncom.CoInitialize()
try:
    w = wmi.WMI()
    query = "SELECT * FROM __InstanceCreationEvent WITHIN 1.0 WHERE TargetInstance ISA 'Win32_Process'"
    watcher = w.watch_for(raw_wql=query)
    
    count = 0
    while True:
        try:
            event = watcher(timeout_ms=1000)
            if event:
                proc = event.TargetInstance
                name = proc.Name
                count += 1
                print(f"[{count}] DETECTED: {name}")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print(f"\n\n✅ Test complete. Detected {count} processes.")
            break
        except Exception as e:
            print(f"⚠️ Error: {e}")
            
finally:
    pythoncom.CoUninitialize()
