"""
main.py — Entry point for the Hybrid Network Monitoring Agent
Starts the SNMP polling thread and the ICMP probe thread, then keeps
the process alive so both daemon threads continue running.

Usage:
    python main.py

Keep this running in one terminal, then open a second terminal and run:
    streamlit run dashboard.py
"""

import time
import database
import snmp_monitor
import icmp_monitor

if __name__ == "__main__":
    print("=" * 60)
    print("  Hybrid Network Monitoring Agent  —  SNMP + ICMP")
    print("=" * 60)

    # Initialise the SQLite database (creates tables if needed)
    database.init_db()

    # Start both monitoring threads
    snmp_thread = snmp_monitor.start()
    icmp_thread = icmp_monitor.start()

    print("\n[MAIN] Both monitoring threads are running.")
    print("[MAIN] Open a new terminal and run:  streamlit run dashboard.py")
    print("[MAIN] Press Ctrl+C to stop.\n")

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[MAIN] Shutting down — goodbye.")
