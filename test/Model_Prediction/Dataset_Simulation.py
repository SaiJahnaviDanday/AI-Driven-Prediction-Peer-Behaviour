import pandas as pd
import random
import csv
from datetime import datetime, timedelta
import uuid
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Define GOOD_TESTS, MALICIOUS_TESTS, and SUSPICIOUS_TESTS
GOOD_TESTS = [
    "approved_edit_global_resource_table_sgh",
    "approved_delete_global_resource_table_pgh",
    "approved_delete_global_resource_table_sgh",
    "access_local_resource",
    "view_local_resource_pgh",
    "view_local_resource_sgh",
    "view_global_resource_sgh",
    "edit_global_resource_pgh"
]
MALICIOUS_TESTS = [
    "unauthorized_view_global_resource_table_rm",
    "unauthorized_global_access",
    "access_another_local_resource",
    "data_tampering",
    "unauthorized_edit",
    "unauthorized_delete",
    "dos_attack"
]
SUSPICIOUS_TESTS = [
    "too_frequent_access"
]

# Combine all test cases
TEST_CASES = GOOD_TESTS + MALICIOUS_TESTS + SUSPICIOUS_TESTS

# Define constants
ROLES = ["PRIMARY_GROUP_HEAD", "SECONDARY_GROUP_HEAD", "REGULAR_MEMBER"]
TYPES = ["type1", "type2", "type3", "type4"]
STATUSES = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
RESOURCES = ["GlobalResourceTable", "LocalResourceTable"]
ACTIONS = ["view", "edit", "delete"]

BALANCES = {
    "PRIMARY_GROUP_HEAD": 1000000000000000000000000,
    "SECONDARY_GROUP_HEAD": 500000000000000000000000,
    "REGULAR_MEMBER": 100000000000000000000000,
}

PENALTIES = {
    "Unauthorized access attempt": 5000,
    "Too frequent access": 3000,
    "Tampering with data": 8000,
    "Denial of Service": 20000,
}

BLOCK_DURATIONS = {
    "Unauthorized access attempt": 3600,
    "Too frequent access": 600,
    "Tampering with data": 10800,
    "Denial of Service": 172800,
}

def generate_member_address(num_members=100):
    return [f"0x{uuid.uuid4().hex[:40]}" for _ in range(num_members)]

def generate_member_name(role, index):
    if role == "PRIMARY_GROUP_HEAD":
        return f"primary_head{index}"
    elif role == "SECONDARY_GROUP_HEAD":
        return f"secondary_group_head{index}"
    else:
        return f"regular_member{index}"

def simulate_test_case(member_address, member_name, role, member_type, prev_behavior=None):
    # Bias test selection based on previous behavior to create strong patterns
    if prev_behavior == 2 and random.random() < 0.85:  # 85% chance to repeat malicious
        test_name = random.choice(MALICIOUS_TESTS)
    elif prev_behavior == 1 and random.random() < 0.85:  # 85% chance to repeat suspicious
        test_name = random.choice(SUSPICIOUS_TESTS)
    elif prev_behavior == 0 and random.random() < 0.85:  # 85% chance to repeat good
        test_name = random.choice(GOOD_TESTS)
    else:
        test_name = random.choice(TEST_CASES)
    
    initial_status = random.choice(STATUSES) if random.random() > 0.8 else "BENIGN"
    timestamp = datetime.now() + timedelta(seconds=random.randint(0, 100000))
    last_status_update = (datetime.now() - timedelta(days=random.randint(0, 10))).strftime("%m/%d/%Y, %I:%M:%S %p")
    gas_used = random.randint(200000, 350000)
    execution_time = round(random.uniform(300, 600), 2)
    balance_before = BALANCES[role]
    reward = 0
    penalty = 0
    delay = 0
    blocking_end_time = "Not Blocked"
    final_status = initial_status
    is_status_changed = 0
    latency = execution_time

    if test_name in GOOD_TESTS:
        if (role == "PRIMARY_GROUP_HEAD" and test_name in ["approved_delete_global_resource_table_pgh", "view_local_resource_pgh", "edit_global_resource_pgh"]) or \
           (role == "SECONDARY_GROUP_HEAD" and test_name in ["approved_edit_global_resource_table_sgh", "approved_delete_global_resource_table_sgh", "view_local_resource_sgh", "view_global_resource_sgh"]) or \
           (role == "REGULAR_MEMBER" and test_name == "access_local_resource"):
            reward = 5000 if random.random() > 0.2 else 0
            balance_after = balance_before + reward
            final_status = "BENIGN"
            delay = random.randint(0, 3600)
        else:
            reason = "Unauthorized access attempt"
            penalty = PENALTIES[reason]
            balance_after = balance_before - penalty
            final_status = "MALICIOUS"
            blocking_end_time = (datetime.now() + timedelta(seconds=BLOCK_DURATIONS[reason])).strftime("%m/%d/%Y, %I:%M:%S %p")
            delay = BLOCK_DURATIONS[reason]
            is_status_changed = 1 if initial_status != final_status else 0
    elif test_name in MALICIOUS_TESTS:
        reason = "Unauthorized access attempt" if test_name in ["unauthorized_view_global_resource_table_rm", "unauthorized_global_access", "access_another_local_resource"] else \
                 "Tampering with data" if test_name in ["data_tampering", "unauthorized_edit", "unauthorized_delete"] else \
                 "Denial of Service"
        penalty = PENALTIES[reason]
        balance_after = balance_before - penalty
        final_status = "MALICIOUS"
        blocking_end_time = (datetime.now() + timedelta(seconds=BLOCK_DURATIONS[reason])).strftime("%m/%d/%Y, %I:%M:%S %p")
        delay = BLOCK_DURATIONS[reason]
        is_status_changed = 1 if initial_status != final_status else 0
    elif test_name in SUSPICIOUS_TESTS:
        reason = "Too frequent access"
        penalty = PENALTIES[reason]
        balance_after = balance_before - penalty
        final_status = "SUSPICIOUS"
        blocking_end_time = (datetime.now() + timedelta(seconds=BLOCK_DURATIONS[reason])).strftime("%m/%d/%Y, %I:%M:%S %p")
        delay = BLOCK_DURATIONS[reason]
        is_status_changed = 1 if initial_status != final_status else 0

    return {
        "timestamp": timestamp,
        "member": member_address,
        "name": member_name,
        "type": member_type,
        "role": role,
        "initial_status": initial_status,
        "final_status": final_status,
        "last_status_update": last_status_update,
        "test_name": test_name,
        "gas_used": gas_used,
        "execution_time": execution_time,
        "balance_before": balance_before,
        "balance_after": balance_after,
        "reward": reward,
        "penalty": penalty,
        "delay": delay,
        "latency": latency,
        "blocking_end_time": blocking_end_time,
        "is_status_changed": is_status_changed
    }

def generate_dataset(num_rows=3000):
    data = []
    num_members = 100
    members = generate_member_address(num_members)
    actions_per_member = [random.randint(15, 35) for _ in range(num_members)]
    
    for i, member in enumerate(members):
        role = random.choice(ROLES)
        member_name = generate_member_name(role, i % 4 + 1)
        member_type = random.choice(TYPES)
        prev_behavior = None
        for _ in range(actions_per_member[i]):
            row = simulate_test_case(member, member_name, role, member_type, prev_behavior)
            data.append(row)
            prev_behavior = 0 if row['test_name'] in GOOD_TESTS else 1 if row['test_name'] in SUSPICIOUS_TESTS else 2
    
    random.shuffle(data)
    df = pd.DataFrame(data[:3000])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    # Add behavior and next_behavior
    df['behavior'] = df['test_name'].apply(lambda x: 0 if x in GOOD_TESTS else 1 if x in SUSPICIOUS_TESTS else 2)
    df = df.sort_values(by=['member', 'timestamp'])
    
    # Add new features
    df['action_count'] = df.groupby('member').cumcount() + 1
    df['recent_malicious'] = df.groupby('member')['behavior'].shift(1).rolling(window=3, min_periods=1).sum().fillna(0)
    df['time_since_last'] = df.groupby('member')['timestamp'].diff().apply(lambda x: x.total_seconds() if pd.notna(x) else 0)
    df['malicious_ratio'] = df.groupby('member')['behavior'].transform(lambda x: x.rolling(window=10, min_periods=1).mean().shift(1)).fillna(0)
    df['action_type_freq'] = df.groupby('member')['test_name'].transform(lambda x: x.map(x.value_counts(normalize=True)))
    df['time_since_last_penalty'] = df.groupby('member')['penalty'].shift(1).rolling(window=5, min_periods=1).sum().fillna(0)
    df['role_behavior_interaction'] = df['role'].astype(str) + '_' + df['behavior'].astype(str)
    df['penalty_severity'] = df['penalty'] / df['penalty'].max()  # Normalize penalty
    df['action_sequence_length'] = df.groupby('member')['behavior'].transform(lambda x: (x != x.shift()).cumsum())
    
    # Convert balance columns to float64 to handle large values
    df['balance_before'] = df['balance_before'].astype('float64')
    df['balance_after'] = df['balance_after'].astype('float64')
    
    # Create next behavior
    df['next_behavior'] = df.groupby('member')['behavior'].shift(-1)
    df = df.dropna(subset=['next_behavior'])
    df['next_behavior'] = df['next_behavior'].astype(int)
    logging.info(f"Rows after dropping NaN next_behavior: {len(df)}")
    
    return df

# Generate and save dataset
df = generate_dataset(3000)
df.to_csv("simulated_access_control_dataset.csv", index=False)
logging.info("Dataset saved to 'simulated_access_control_dataset.csv'")