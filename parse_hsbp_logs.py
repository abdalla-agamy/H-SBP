# --- START OF FILE parse_hsbp_logs.py ---
import re
import os
import json
import statistics
from pathlib import Path
from collections import defaultdict
import sys

# --- Configuration ---
# LOG_DIR = Path("./logs")
# CONFIG_FILE_FOR_STRUCTURE = Path("./config/hsbp_config.json")
# For Docker
LOG_DIR = Path("/mnt/workarea/H-SBP/logs")
CONFIG_FILE_FOR_STRUCTURE = Path("/mnt/workarea/H-SBP/config/hsbp_config.json")
TARGET_CLUSTER_ID_FOR_METRICS = "1"
# --- End Configuration ---

# --- Regex Patterns (Keep as before) ---
# SL Logs
sl_ch_join_time_pattern = re.compile(r"\[SL\] Execution time for CH (ch-\d+) join event calculation: ([\d\.]+) ms")
sl_ch_join_length_pattern = re.compile(r"\[SL\] Key update message length for CH_join\((ch-\d+)\): (\d+) bytes")
sl_ch_leave_time_pattern = re.compile(r"\[SL\] Execution time for (\d+) CHs batch leave event calculation: ([\d\.]+) ms")
sl_ch_leave_length_pattern = re.compile(r"\[SL\] Key update message length for CH_leave\((.*?)\): (\d+) bytes")
# CH Logs
ch_as_follower_sl_join_time_pattern = re.compile(r"\[CH\] As-follower, Execution time for joining SL key computation : ([\d\.]+) ms")
# ch_m0_init_time_pattern = re.compile(r"Initial K_cluster computed \(M0 members\):.*?\(took ([\d\.]+) ms\)") # Removed
# ch_m0_init_length_pattern = re.compile(r"\[CH\] Key update message length for initial_setup: (\d+) bytes") # Removed
ch_member_join_time_pattern = re.compile(r"\[CH\] Execution time for single join event \((m-\d+\d*)\): ([\d\.]+) ms")
ch_member_join_length_pattern = re.compile(r"\[CH\] Key update message length for single_join\((m-\d+\d*)\): (\d+) bytes")
ch_batch_leave_time_pattern = re.compile(r"\[CH\] Execution time for (\d+) members batch leave event: ([\d\.]+) ms")
ch_batch_leave_length_pattern = re.compile(r"\[CH\] Key update message length for batch_leave: (\d+) bytes")
# Member Logs
member_joining_time_pattern = re.compile(r"\[MEMBER\] Execution time for joining key computation: ([\d\.]+) ms")
member_post_leave_time_pattern = re.compile(r"\[MEMBER\] Execution time for key computation \(full state\): ([\d\.]+) ms")
# --- End Regex Patterns ---

def parse_log_file(file_path, patterns):
    """Parses a single log file for multiple regex patterns."""
    # ... (Keep function as before) ...
    results = defaultdict(list)
    try:
        with open(file_path, 'r') as f:
            for line in f:
                for key, pattern in patterns.items():
                    match = pattern.search(line)
                    if match:
                        if len(match.groups()) == 1:
                            try: results[key].append(float(match.group(1)))
                            except ValueError: results[key].append(match.group(1))
                        else:
                            processed_groups = []
                            for group_val in match.groups():
                                try: processed_groups.append(float(group_val))
                                except ValueError: processed_groups.append(group_val)
                            results[key].append(tuple(processed_groups))
                        break
    except FileNotFoundError: print(f"Warning: Log file not found: {file_path}")
    except Exception as e: print(f"Error parsing file {file_path}: {e}")
    return results

def calculate_stats(values):
    """Calculates min, max, mean, count for a list of numbers."""
    # ... (Keep function as before) ...
    numeric_values = [x for x in values if isinstance(x, (int, float))]
    if not numeric_values:
        return {"min": "N/A", "max": "N/A", "mean": "N/A", "count": len(values), "all": values}
    return {
        "min": min(numeric_values), "max": max(numeric_values),
        "mean": statistics.mean(numeric_values), "count": len(numeric_values),
        "all_entries": values
    }

# --- NEW: Modified print_metric_stats for table row ---
def print_table_row(role, Act_as, event, metric, unit, data_list):
    """Prints a single row for the metrics table."""
    stats = calculate_stats(data_list)
    min_s = f"{stats['min']:.3f}" if isinstance(stats['min'], float) else str(stats['min'])
    max_s = f"{stats['max']:.3f}" if isinstance(stats['max'], float) else str(stats['max'])
    mean_s = f"{stats['mean']:.3f}" if isinstance(stats['mean'], float) else str(stats['mean'])
    if unit == "bytes": # No decimals for bytes
        min_s = f"{stats['min']:.0f}" if isinstance(stats['min'], float) else str(stats['min'])
        max_s = f"{stats['max']:.0f}" if isinstance(stats['max'], float) else str(stats['max'])
        mean_s = f"{stats['mean']:.0f}" if isinstance(stats['mean'], float) else str(stats['mean'])

    print(f"| {role:<12} | {Act_as:<10}| {event:<25} | {metric + ' (' + unit + ')':<20} | {min_s:>7} | {max_s:>7} | {mean_s:>7} | {str(stats['count']):>5} |")
# --- END NEW ---


def main():
    if not LOG_DIR.is_dir(): print(f"Log directory not found: {LOG_DIR}"); return
    if len(sys.argv) == 2:  # If arguments are provided
        num_total_followers = int(sys.argv[1])
    else:  # Fall back to interactive input
        num_total_followers = int(input("Enter total number of followers (e.g., 1000, 2000): "))
        
    try:
        with open(CONFIG_FILE_FOR_STRUCTURE, 'r') as f: config_data = json.load(f)
        sl_id_config = config_data['structure']['sl_id']
        target_ch_config = config_data['structure']['clusters'][TARGET_CLUSTER_ID_FOR_METRICS]
        target_ch_id_config = target_ch_config['ch_id']
        target_joining_member_id_config = target_ch_config.get('joining_member')
    except Exception as e: print(f"Error loading config {CONFIG_FILE_FOR_STRUCTURE}: {e}"); return

    all_metrics = {
        "sl": defaultdict(list),
        "ch": defaultdict(lambda: defaultdict(list)),
        "member": defaultdict(lambda: defaultdict(list))
    }

    # Parse SL log
    sl_log_file = LOG_DIR / f"{sl_id_config}.log"; sl_patterns = {"ch_join_time": sl_ch_join_time_pattern, "ch_join_length": sl_ch_join_length_pattern}
    sl_log_results = parse_log_file(sl_log_file, sl_patterns)
    sl_target_ch_join_times = [x[1] for x in sl_log_results.get("ch_join_time", []) if x[0] == target_ch_id_config]
    sl_target_ch_join_lengths = [x[1] for x in sl_log_results.get("ch_join_length", []) if x[0] == target_ch_id_config]

    # Parse Target CH log
    ch_log_file = LOG_DIR / f"{target_ch_id_config}.log"
    ch_patterns = {
        "as_follower_time": ch_as_follower_sl_join_time_pattern,
        "member_join_event": ch_member_join_time_pattern,
        "member_join_length_event": ch_member_join_length_pattern,
        "batch_leave_time": ch_batch_leave_time_pattern,
        "batch_leave_length": ch_batch_leave_length_pattern,
    }
    ch_log_results = parse_log_file(ch_log_file, ch_patterns)
    ch_as_follower_times = ch_log_results.get("as_follower_time", [])
    ch_single_member_join_times = [x[1] for x in ch_log_results.get("member_join_event", []) if x[0] == target_joining_member_id_config]
    ch_single_member_join_lengths = [x[1] for x in ch_log_results.get("member_join_length_event", []) if x[0] == target_joining_member_id_config]
    ch_batch_leave_times = [x[1] for x in ch_log_results.get("batch_leave_time", [])] # Time is group 2
    ch_batch_leave_lengths = [x for x in ch_log_results.get("batch_leave_length", [])] # Length is group 2

    # Parse Target Joining Member log
    member_joining_times = []; member_post_leave_times = []
    if target_joining_member_id_config:
        member_log_file = LOG_DIR / f"{target_joining_member_id_config}.log"
        member_patterns = {"joining_time": member_joining_time_pattern, "post_leave_key_comp_time": member_post_leave_time_pattern}
        member_log_results = parse_log_file(member_log_file, member_patterns)
        member_joining_times = member_log_results.get("joining_time",[])
        member_post_leave_times = member_log_results.get("post_leave_key_comp_time",[])

    # --- Print Statistics Table ---
    print(f"\n\n========= H-SBP METRICS (For {num_total_followers} followers) =========")
    header = f"| {'Role':<12} | {'Act As':<10}| {'Event':<25} | {'Metric':<20} | {'Min':>7} | {'Max':>7} | {'Mean':>7} | {'Count':>5} |"
    print("=" * len(header))
    print(header)
    print("=" * len(header))

    # SL Metrics
    if sl_target_ch_join_times or sl_target_ch_join_lengths:
        print_table_row("SL","Leader", f"Join ({target_ch_id_config})", "Calc Time", "ms", sl_target_ch_join_times)
        print_table_row("SL","Leader", f"Join ({target_ch_id_config})", "Msg Len", "bytes", sl_target_ch_join_lengths)
        print("-" * len(header))

    # Target CH Metrics
    print_table_row(f"CH({target_ch_id_config})","Follower", "Join (SL)", "Time", "ms", ch_as_follower_times)
    print_table_row(f"CH({target_ch_id_config})","Leader", f"Join ({target_joining_member_id_config})", "Calc Time", "ms", ch_single_member_join_times)
    print_table_row(f"CH({target_ch_id_config})","Leader", f"Join ({target_joining_member_id_config})", "Msg Len", "bytes", ch_single_member_join_lengths)
    print_table_row(f"CH({target_ch_id_config})","Leader", "Batch Leave", "Calc Time", "ms", ch_batch_leave_times)
    print_table_row(f"CH({target_ch_id_config})","Leader", "Batch Leave", "Msg Len", "bytes", ch_batch_leave_lengths)
    print("-" * len(header))

    # Target Joining Member Metrics
    if target_joining_member_id_config:
        print_table_row(f"Member({target_joining_member_id_config})","Follower", f"Joining ({target_ch_id_config})", "Time", "ms", member_joining_times)
        print_table_row(f"Member({target_joining_member_id_config})","Follower", f"Post-Leave ({target_ch_id_config})", "Time", "ms", member_post_leave_times)

    print("=" * len(header))


if __name__ == "__main__":
    main()
# --- END OF FILE parse_hsbp_logs.py ---
