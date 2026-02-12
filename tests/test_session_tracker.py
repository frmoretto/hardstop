#!/usr/bin/env python3
"""
Test suite for session tracker.
"""

import pytest
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

# Add hooks directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "hooks"))

from session_tracker import SessionTracker, get_tracker, HARDSTOP_DIR, SESSION_FILE


@pytest.fixture
def temp_session_dir(tmp_path, monkeypatch):
    """Create temporary session directory for testing."""
    test_dir = tmp_path / ".hardstop"
    test_dir.mkdir()
    test_session_file = test_dir / "session.json"

    # Monkey patch the module-level constants
    import session_tracker
    monkeypatch.setattr(session_tracker, 'HARDSTOP_DIR', test_dir)
    monkeypatch.setattr(session_tracker, 'SESSION_FILE', test_session_file)

    # Clear environment variable
    if 'HARDSTOP_SESSION_ID' in os.environ:
        del os.environ['HARDSTOP_SESSION_ID']

    # Reset singleton so each test gets a fresh tracker
    monkeypatch.setattr(session_tracker, '_tracker', None)

    return test_dir


@pytest.fixture
def tracker(temp_session_dir):
    """Create a fresh session tracker for testing."""
    return SessionTracker()


class TestSessionTrackerInit:
    """Test session tracker initialization."""

    def test_creates_new_session(self, tracker):
        """Test that tracker creates a new session."""
        assert tracker.session_id is not None
        assert tracker.data is not None
        assert tracker.data['risk_score'] == 0
        assert tracker.data['blocked_commands'] == []

    def test_session_id_from_timestamp(self, tracker):
        """Test that session ID is timestamp-based."""
        # Session ID should match YYYYMMDD_HHMMSS format
        assert len(tracker.session_id) == 15
        assert '_' in tracker.session_id

    def test_session_id_from_environment(self, temp_session_dir):
        """Test that session ID can come from environment."""
        os.environ['HARDSTOP_SESSION_ID'] = 'test_session_123'
        tracker = SessionTracker()
        assert tracker.session_id == 'test_session_123'


class TestRecordBlock:
    """Test recording blocked commands."""

    def test_records_basic_block(self, tracker):
        """Test recording a simple blocked command."""
        pattern_data = {
            'id': 'TEST_PATTERN',
            'severity': 'high',
            'message': 'Test dangerous pattern',
            'category': 'network',
        }

        tracker.record_block("rm -rf /", pattern_data)

        assert tracker.get_blocked_count() == 1
        assert tracker.get_risk_score() == 15  # high = 15 points

    def test_accumulates_risk_score(self, tracker):
        """Test that risk score accumulates across multiple blocks."""
        pattern1 = {'severity': 'high', 'message': 'High risk'}
        pattern2 = {'severity': 'medium', 'message': 'Medium risk'}
        pattern3 = {'severity': 'critical', 'message': 'Critical risk'}

        tracker.record_block("cmd1", pattern1)  # +15
        tracker.record_block("cmd2", pattern2)  # +10
        tracker.record_block("cmd3", pattern3)  # +25

        assert tracker.get_risk_score() == 50  # 15 + 10 + 25
        assert tracker.get_blocked_count() == 3

    def test_stores_all_pattern_data(self, tracker):
        """Test that all pattern data is stored in block record."""
        pattern_data = {
            'id': 'DANGEROUS_COMMAND',
            'severity': 'critical',
            'message': 'Deletes root filesystem',
            'category': 'filesystem',
            'mitre_attack': 'T1485',
        }

        tracker.record_block("rm -rf /", pattern_data)

        blocked = tracker.get_blocked_commands()
        assert len(blocked) == 1

        record = blocked[0]
        assert record['command'] == "rm -rf /"
        assert record['severity'] == 'critical'
        assert record['message'] == 'Deletes root filesystem'
        assert record['category'] == 'filesystem'
        assert record['mitre_attack'] == 'T1485'
        assert record['pattern_id'] == 'DANGEROUS_COMMAND'
        assert 'timestamp' in record

    def test_truncates_long_commands(self, tracker):
        """Test that very long commands are truncated."""
        long_command = "x" * 300
        pattern_data = {'severity': 'low', 'message': 'Test'}

        tracker.record_block(long_command, pattern_data)

        blocked = tracker.get_blocked_commands()
        assert len(blocked[0]['command']) == 200

    def test_defaults_to_medium_severity(self, tracker):
        """Test that missing severity defaults to medium."""
        pattern_data = {'message': 'Test pattern'}  # No severity

        tracker.record_block("test", pattern_data)

        assert tracker.get_risk_score() == 10  # medium = 10


class TestGetRiskLevel:
    """Test risk level calculation."""

    def test_low_risk_level(self, tracker):
        """Test that low score gives low risk level."""
        pattern = {'severity': 'info', 'message': 'Info'}
        tracker.record_block("cmd", pattern)  # 1 point

        assert tracker.get_risk_level() == "low"

    def test_moderate_risk_level(self, tracker):
        """Test that moderate score gives moderate risk level."""
        pattern = {'severity': 'high', 'message': 'High'}
        tracker.record_block("cmd1", pattern)  # 15
        tracker.record_block("cmd2", pattern)  # 15
        # Total: 30 = moderate

        assert tracker.get_risk_level() == "moderate"

    def test_high_risk_level(self, tracker):
        """Test that high score gives high risk level."""
        pattern = {'severity': 'critical', 'message': 'Critical'}
        tracker.record_block("cmd1", pattern)  # 25
        tracker.record_block("cmd2", pattern)  # 25
        # Total: 50 = high

        assert tracker.get_risk_level() == "high"

    def test_critical_risk_level(self, tracker):
        """Test that very high score gives critical risk level."""
        pattern = {'severity': 'critical', 'message': 'Critical'}
        for i in range(4):
            tracker.record_block(f"cmd{i}", pattern)  # 25 * 4 = 100

        assert tracker.get_risk_level() == "critical"


class TestSessionInfo:
    """Test session information retrieval."""

    def test_get_session_info(self, tracker):
        """Test getting complete session info."""
        info = tracker.get_session_info()

        assert 'session_id' in info
        assert 'started_at' in info
        assert 'risk_score' in info
        assert 'risk_level' in info
        assert 'blocked_count' in info
        assert info['risk_score'] == 0
        assert info['blocked_count'] == 0

    def test_session_info_after_blocks(self, tracker):
        """Test session info after recording blocks."""
        pattern = {'severity': 'high', 'message': 'Test'}
        tracker.record_block("cmd", pattern)

        info = tracker.get_session_info()
        assert info['blocked_count'] == 1
        assert info['risk_score'] == 15
        assert info['risk_level'] == 'low'  # 15 = still low
        assert 'last_blocked_at' in info

    def test_severity_breakdown(self, tracker):
        """Test getting breakdown of blocks by severity."""
        tracker.record_block("cmd1", {'severity': 'critical', 'message': 'Test'})
        tracker.record_block("cmd2", {'severity': 'critical', 'message': 'Test'})
        tracker.record_block("cmd3", {'severity': 'high', 'message': 'Test'})
        tracker.record_block("cmd4", {'severity': 'medium', 'message': 'Test'})

        breakdown = tracker.get_severity_breakdown()
        assert breakdown['critical'] == 2
        assert breakdown['high'] == 1
        assert breakdown['medium'] == 1
        assert breakdown['low'] == 0
        assert breakdown['info'] == 0


class TestPersistence:
    """Test session data persistence."""

    def test_saves_to_disk(self, tracker, temp_session_dir):
        """Test that session data is saved to disk."""
        pattern = {'severity': 'high', 'message': 'Test'}
        tracker.record_block("cmd", pattern)

        session_file = temp_session_dir / "session.json"
        assert session_file.exists()

        with open(session_file) as f:
            data = json.load(f)

        assert data['risk_score'] == 15
        assert len(data['blocked_commands']) == 1

    def test_loads_from_disk(self, tracker, temp_session_dir):
        """Test that session data persists across instances."""
        pattern = {'severity': 'critical', 'message': 'Test'}
        tracker.record_block("cmd", pattern)

        # Create new tracker with same session ID
        os.environ['HARDSTOP_SESSION_ID'] = tracker.session_id
        tracker2 = SessionTracker()

        assert tracker2.get_risk_score() == 25
        assert tracker2.get_blocked_count() == 1

    def test_handles_corrupted_file(self, tracker, temp_session_dir):
        """Test that corrupted session file is handled gracefully."""
        session_file = temp_session_dir / "session.json"

        # Write invalid JSON
        with open(session_file, 'w') as f:
            f.write("{ invalid json }")

        # Should create new session instead of crashing
        tracker2 = SessionTracker()
        assert tracker2.get_risk_score() == 0


class TestSaveSessionError:
    """Test _save_session error handling."""

    def test_save_session_io_error(self, tracker, temp_session_dir):
        """Test that IOError during _save_session is handled gracefully (lines 94-95)."""
        pattern = {'severity': 'high', 'message': 'Test'}

        # Mock open to raise IOError during save
        with patch("builtins.open", side_effect=IOError("disk full")):
            # record_block calls _save_session internally; should not crash
            tracker.record_block("cmd", pattern)

        # Data should still be updated in memory
        assert tracker.get_risk_score() == 15
        assert tracker.get_blocked_count() == 1


class TestSessionReset:
    """Test session reset functionality."""

    def test_reset_session(self, tracker):
        """Test that reset creates new session."""
        import time
        # Add some data
        pattern = {'severity': 'high', 'message': 'Test'}
        tracker.record_block("cmd", pattern)
        old_session_id = tracker.session_id
        old_started_at = tracker.data['started_at']

        # Wait a moment to ensure different timestamp
        time.sleep(0.01)

        # Reset
        tracker.reset_session()

        # Session ID or start time should be different
        assert (tracker.session_id != old_session_id or
                tracker.data['started_at'] != old_started_at)
        assert tracker.get_risk_score() == 0
        assert tracker.get_blocked_count() == 0

    def test_clear_history(self, tracker):
        """Test that clear_history resets data but keeps session."""
        # Add some data
        pattern = {'severity': 'high', 'message': 'Test'}
        tracker.record_block("cmd", pattern)
        session_id = tracker.session_id

        # Clear history
        tracker.clear_history()

        assert tracker.session_id == session_id  # Same session
        assert tracker.get_risk_score() == 0     # But data cleared
        assert tracker.get_blocked_count() == 0


class TestGlobalTracker:
    """Test global tracker singleton."""

    def test_get_tracker_returns_singleton(self, temp_session_dir):
        """Test that get_tracker returns same instance."""
        tracker1 = get_tracker()
        tracker2 = get_tracker()

        assert tracker1 is tracker2

    def test_singleton_persists_state(self, temp_session_dir):
        """Test that singleton maintains state."""
        tracker1 = get_tracker()
        pattern = {'severity': 'high', 'message': 'Test'}
        tracker1.record_block("cmd", pattern)

        tracker2 = get_tracker()
        assert tracker2.get_risk_score() == 15
