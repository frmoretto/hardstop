#!/usr/bin/env python3
"""
Session-based risk tracking for Hardstop.

Tracks blocked commands and cumulative risk score per session.
Persists data to ~/.hardstop/session.json

Part of Hardstop v1.4.0 - Phase 2.3: Risk Scoring System
"""

import json
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
from risk_scoring import SEVERITY_WEIGHTS, calculate_risk_level, get_severity_weight

HARDSTOP_DIR = Path.home() / ".hardstop"
SESSION_FILE = HARDSTOP_DIR / "session.json"


class SessionTracker:
    """Track session risk and blocked commands."""

    def __init__(self):
        """Initialize session tracker."""
        self.session_id = self._get_session_id()
        self.data = self._load_session()

    def _get_session_id(self) -> str:
        """
        Get or create session ID.

        Uses HARDSTOP_SESSION_ID environment variable if set,
        otherwise creates a new session ID from current timestamp.

        Returns:
            Session ID string
        """
        session_id = os.environ.get('HARDSTOP_SESSION_ID')
        if not session_id:
            session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
            os.environ['HARDSTOP_SESSION_ID'] = session_id
        return session_id

    def _load_session(self) -> Dict:
        """
        Load session data from disk.

        If session file exists and session ID matches, loads existing data.
        Otherwise creates a new session.

        Returns:
            Session data dictionary
        """
        if SESSION_FILE.exists():
            try:
                with open(SESSION_FILE) as f:
                    data = json.load(f)
                    # Reset if session ID changed
                    if data.get('session_id') != self.session_id:
                        return self._create_new_session()
                    return data
            except (json.JSONDecodeError, IOError) as e:
                # If file is corrupted, create new session
                print(f"Warning: Failed to load session data: {e}", flush=True)
                return self._create_new_session()
        return self._create_new_session()

    def _create_new_session(self) -> Dict:
        """
        Create new session data structure.

        Returns:
            New session dictionary with initial values
        """
        return {
            'session_id': self.session_id,
            'started_at': datetime.now().isoformat(),
            'risk_score': 0,
            'blocked_commands': [],
        }

    def _save_session(self):
        """
        Persist session data to disk.

        Creates ~/.hardstop directory if it doesn't exist.
        """
        try:
            HARDSTOP_DIR.mkdir(parents=True, exist_ok=True)
            with open(SESSION_FILE, 'w') as f:
                json.dump(self.data, f, indent=2)
        except IOError as e:
            print(f"Warning: Failed to save session data: {e}", flush=True)

    def record_block(self, command: str, pattern_data: Dict):
        """
        Record a blocked command and update risk score.

        Args:
            command: The command that was blocked
            pattern_data: Pattern information including severity, message, etc.
        """
        severity = pattern_data.get('severity', 'medium')
        weight = get_severity_weight(severity)

        block_record = {
            'timestamp': datetime.now().isoformat(),
            'command': command[:200],  # Truncate long commands
            'severity': severity,
            'weight': weight,
            'message': pattern_data.get('message', ''),
            'pattern_id': pattern_data.get('id', ''),
            'mitre_attack': pattern_data.get('mitre_attack'),
            'category': pattern_data.get('category'),
        }

        self.data['blocked_commands'].append(block_record)
        self.data['risk_score'] += weight
        self.data['last_blocked_at'] = datetime.now().isoformat()
        self._save_session()

    def get_risk_score(self) -> int:
        """
        Get current session risk score.

        Returns:
            Current risk score (cumulative weight of all blocked commands)
        """
        return self.data.get('risk_score', 0)

    def get_risk_level(self) -> str:
        """
        Get current risk level based on score.

        Returns:
            Risk level: "low", "moderate", "high", or "critical"
        """
        return calculate_risk_level(self.get_risk_score())

    def get_blocked_commands(self) -> List[Dict]:
        """
        Get list of blocked commands this session.

        Returns:
            List of blocked command records
        """
        return self.data.get('blocked_commands', [])

    def get_blocked_count(self) -> int:
        """
        Get count of blocked commands.

        Returns:
            Number of commands blocked this session
        """
        return len(self.data.get('blocked_commands', []))

    def get_session_info(self) -> Dict:
        """
        Get complete session information.

        Returns:
            Dictionary with session_id, started_at, risk_score, risk_level, blocked_count
        """
        return {
            'session_id': self.session_id,
            'started_at': self.data.get('started_at'),
            'last_blocked_at': self.data.get('last_blocked_at'),
            'risk_score': self.get_risk_score(),
            'risk_level': self.get_risk_level(),
            'blocked_count': self.get_blocked_count(),
        }

    def get_severity_breakdown(self) -> Dict[str, int]:
        """
        Get breakdown of blocked commands by severity.

        Returns:
            Dictionary mapping severity levels to counts
        """
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for cmd in self.get_blocked_commands():
            severity = cmd.get('severity', 'medium')
            if severity in breakdown:
                breakdown[severity] += 1
        return breakdown

    def reset_session(self):
        """
        Reset session data.

        Creates a new session with fresh ID and zero risk score.
        """
        new_session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
        os.environ['HARDSTOP_SESSION_ID'] = new_session_id
        self.session_id = new_session_id

        self.data = {
            'session_id': self.session_id,
            'started_at': datetime.now().isoformat(),
            'risk_score': 0,
            'blocked_commands': [],
        }
        self._save_session()

    def clear_history(self):
        """
        Clear blocked commands history but keep current session.

        Resets risk score and command list while maintaining session ID.
        """
        self.data['risk_score'] = 0
        self.data['blocked_commands'] = []
        if 'last_blocked_at' in self.data:
            del self.data['last_blocked_at']
        self._save_session()


# Global tracker instance (singleton)
_tracker: Optional[SessionTracker] = None


def get_tracker() -> SessionTracker:
    """
    Get global session tracker instance.

    Creates tracker on first call, returns existing instance on subsequent calls.

    Returns:
        SessionTracker instance
    """
    global _tracker
    if _tracker is None:
        _tracker = SessionTracker()
    return _tracker


# Export public API
__all__ = [
    'SessionTracker',
    'get_tracker',
    'HARDSTOP_DIR',
    'SESSION_FILE',
]
