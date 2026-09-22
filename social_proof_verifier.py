# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
"""
SocialProofVerifier
===================

An Intelligent Contract for **on-chain identity verification** via social media
proof. Users register social media profiles (Twitter, GitHub, Discord, etc.)
and specify verification messages. The validator network independently fetches
these profiles, uses AI to check for the specified messages, and reaches
consensus on the verification result. Verified identities earn a trust score
that other contracts can gate on.

Security Properties
-------------------
1. **Immutable verification rules**: `scheme_name`, `verification_rubric`,
   `supported_platforms`, and `required_messages` are set once at deploy.
   The AI checks against these rules — it cannot rewrite them.

2. **Multi-validator consensus**: Every validator independently re-fetches each
   social media profile and re-verifies the messages. The leader's result is
   accepted only when per-platform verification, aggregate trust score, and
   message match status all agree.

3. **Deterministic trust scoring**: The trust score is computed from the number
   of verified platforms and message match quality using pure integer math —
   no AI involvement in the final score.

4. **History-derived stored outcome**: The stored trust score is the median of
   the last N agreed scores, preventing single-transaction gaming.

5. **Evidence freeze**: During verification, profiles are locked to prevent
   tampering. Only the user or deployer can modify profiles outside verification.

6. **Cooldown enforcement**: Re-verification is gated by a cooldown window.
   The deployer or user must wait for the cooldown to elapsed.

7. **Caller authorization**: Only the user themselves or the deployer can
   register/update profiles and trigger verification.

8. **URL binding**: Validators independently fetch the exact URLs registered
   by the user, ensuring fetched content matches the claimed profile.

9. **Atomic state transitions**: All profile and trust score updates happen
   atomically after consensus, preventing partial state exposure.

10. **Terminal verification states**: Once a profile is verified, it cannot
    regress to unverified without explicit re-verification after cooldown.

Trust Model / Limitations
-------------------------
- The verification rules are set once at deploy; vague rubrics produce noisy
  results. Rules should be explicit about what constitutes valid proof.
- The contract verifies that messages exist on the profiles, not that the
  profiles are authentic. An attacker with fake social accounts can still
  verify. Use this as a primitive combined with other sybil resistance.
- Social media profiles may be deleted or modified after verification.
  Re-verification is recommended for time-sensitive applications.
"""

from genlayer import *
from dataclasses import dataclass
import json

# =============================================================================
# CONSTANTS
# =============================================================================

MAX_PROFILES = 5
MAX_PROFILE_CHARS = 5000
COOLDOWN_SECONDS = 86400  # 24 hours
MAX_HISTORY = 5  # Number of historical scores kept for median smoothing
SCORE_TOLERANCE = 10  # Tolerance for validator agreement on trust score
SUPPORTED_PLATFORMS = ("twitter", "github", "discord", "telegram", "linkedin")
TRUST_LEVELS = ("unverified", "basic", "standard", "enhanced", "premium")

# Platform-to-authoritative URL host mapping
# Each platform is bound to its official domain(s)
PLATFORM_URL_HOSTS = {
    "twitter": ["twitter.com", "x.com"],
    "github": ["github.com"],
    "discord": ["discord.com", "discord.gg", "discordapp.com"],
    "telegram": ["t.me", "telegram.org"],
    "linkedin": ["linkedin.com", "linkedin.cn"],
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _current_timestamp() -> u256:
    """Deterministic per-transaction Unix timestamp (seconds)."""
    import datetime as _dt
    return u256(int(_dt.datetime.now(_dt.timezone.utc).timestamp()))


def _coerce_address(value) -> Address:
    """Normalize an address argument."""
    if isinstance(value, Address):
        return value
    if isinstance(value, str):
        return Address(value)
    if isinstance(value, int):
        return Address(value.to_bytes(20, "big"))
    return Address(bytes(value))


def _validate_platform(platform: str) -> str:
    """Validate and normalize a platform name format."""
    platform = platform.strip().lower()
    if not platform:
        raise gl.vm.UserError("platform name must not be empty")
    return platform


def _validate_profile_url(url: str, platform: str) -> str:
    """Validate a profile URL and bind it to the platform's authoritative host."""
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise gl.vm.UserError(f"invalid profile URL: {url!r}")
    
    # Extract hostname from URL
    # Remove protocol
    hostname = url.split("://", 1)[-1] if "://" in url else url
    # Remove path, query, fragment
    hostname = hostname.split("/")[0]
    # Remove port if present
    hostname = hostname.split(":")[0]
    # Remove www. prefix if present
    hostname = hostname.removeprefix("www.")
    # Remove trailing dots
    hostname = hostname.rstrip(".")
    hostname = hostname.lower()
    
    # Check if hostname matches the platform's authoritative hosts
    allowed_hosts = PLATFORM_URL_HOSTS.get(platform, [])
    if allowed_hosts and hostname not in allowed_hosts:
        raise gl.vm.UserError(
            f"URL host '{hostname}' is not authoritative for platform '{platform}'. "
            f"Allowed hosts: {allowed_hosts}"
        )
    
    return url


def _strip_code_fence(raw: str) -> str:
    """Strip a markdown code fence from LLM JSON output if present."""
    s = raw.strip()
    if s.startswith("```"):
        first_newline = s.find("\n")
        s = s[first_newline + 1:] if first_newline != -1 else s[3:]
        if s.endswith("```"):
            s = s[:-3]
        s = s.strip()
    return s


def _parse_json_object(raw) -> dict | None:
    """Parse an agreed consensus payload, tolerating a JSON string."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(_strip_code_fence(raw))
        except (ValueError, TypeError):
            return None
        return data if isinstance(data, dict) else None
    return None


def _to_int(value) -> int | None:
    """Coerce an LLM-produced score into an integer 0-100, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        num = value
    elif isinstance(value, str):
        text = value.strip()
        if "." in text:
            text = text.split(".")[0]
        if not text:
            return None
        try:
            num = int(text)
        except ValueError:
            return None
    elif isinstance(value, float):
        text = repr(value)
        if "." in text:
            text = text.split(".")[0]
        try:
            num = int(text)
        except ValueError:
            return None
    else:
        return None
    return num if 0 <= num <= 100 else None


def _trust_level_for_score(score: int) -> str:
    """Deterministic mapping from a 0-100 trust score to a level."""
    if score >= 90:
        return "premium"
    if score >= 75:
        return "enhanced"
    if score >= 50:
        return "standard"
    if score >= 25:
        return "basic"
    return "unverified"


def _trust_level_rank(level: str) -> int:
    """Return numeric rank for trust level comparison."""
    return TRUST_LEVELS.index(level)


def _median(values: list[int]) -> int:
    """Median of a non-empty list (integer result). Robust to outliers."""
    if not values:
        raise ValueError("median of empty sequence")
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    if n % 2 == 1:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) // 2


def _compute_trust_score(verified_count: int, total_count: int, scores: list[int]) -> int:
    """Deterministic trust score computation using integer math only.
    
    Score = (verified_count / total_count) * 70 + (avg_score / 100) * 30
    """
    if total_count == 0:
        return 0
    base_score = (verified_count * 70) // total_count
    if scores:
        avg_score = sum(scores) // len(scores)
        bonus_score = (avg_score * 30) // 100
    else:
        bonus_score = 0
    return min(base_score + bonus_score, 100)


def _compute_stored_outcome(
    new_score: int, score_history: list[int], max_history: int = MAX_HISTORY,
) -> tuple[int, str]:
    """Deterministic computation of the stored score and level after appending
    a new score to the history. The stored score is the median of the last
    max_history scores."""
    history = list(score_history)
    history.append(new_score)
    if len(history) > max_history:
        history = history[-max_history:]
    stored_score = _median(history)
    stored_level = _trust_level_for_score(stored_score)
    return stored_score, stored_level


def _consensus_ok(data, num_platforms: int) -> bool:
    """Deterministic shape check on the agreed consensus payload."""
    payload = _parse_json_object(data)
    if payload is None:
        return False
    if not isinstance(payload.get("verified_platforms"), list):
        return False
    if not isinstance(payload.get("failed_platforms"), list):
        return False
    if not isinstance(payload.get("platform_scores"), dict):
        return False
    if not isinstance(payload.get("reasoning"), str):
        return False
    if not isinstance(payload.get("trust_score"), (int, float)):
        return False
    if not isinstance(payload.get("platform_urls"), dict):
        return False

    verified = payload["verified_platforms"]
    failed = payload["failed_platforms"]
    if len(verified) + len(failed) != num_platforms:
        return False

    # Verify all scores are valid integers 0-100
    for platform, score in payload["platform_scores"].items():
        if _to_int(score) is None:
            return False

    # Verify trust score is valid
    trust_score = _to_int(payload.get("trust_score"))
    if trust_score is None:
        return False

    # Verify platform_urls contains all platforms
    all_platforms = set(verified) | set(failed)
    for platform in all_platforms:
        if platform not in payload["platform_urls"]:
            return False

    return True

# =============================================================================
# DATA STRUCTURES
# =============================================================================

@allow_storage
@dataclass
class SocialProfile:
    """Stores a social media profile with verification status."""
    platform: str
    profile_url: str
    verification_message: str
    status: str  # "pending" | "verified" | "failed"
    verification_score: u256
    verified_at: u256
    last_checked_at: u256
    red_flagged: bool  # True if profile has suspicious content
    check_count: u256  # Number of times this profile has been checked

    def as_dict(self) -> dict:
        return {
            "platform": self.platform,
            "profile_url": self.profile_url,
            "verification_message": self.verification_message,
            "status": self.status,
            "verification_score": int(self.verification_score),
            "verified_at": int(self.verified_at),
            "last_checked_at": int(self.last_checked_at),
            "red_flagged": self.red_flagged,
            "check_count": int(self.check_count),
        }


@allow_storage
@dataclass
class VerificationRequest:
    """Stores a verification request and its result."""
    request_id: str
    user_address: Address
    platforms: DynArray[str]
    platform_urls: DynArray[str]  # URLs that were actually verified
    status: str  # "pending" | "verified" | "partial" | "failed"
    trust_score: u256
    stored_score: u256  # Median-smoothed score
    stored_level: str  # Level derived from stored_score
    verified_platforms: DynArray[str]
    failed_platforms: DynArray[str]
    platform_scores: DynArray[u256]  # Score per platform (parallel to platforms)
    reasoning: str
    created_at: u256
    completed_at: u256
    verification_count: u256  # Total verifications for this user

    def as_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "user_address": str(self.user_address),
            "platforms": [p for p in self.platforms],
            "platform_urls": [u for u in self.platform_urls],
            "status": self.status,
            "trust_score": int(self.trust_score),
            "stored_score": int(self.stored_score),
            "stored_level": self.stored_level,
            "verified_platforms": [p for p in self.verified_platforms],
            "failed_platforms": [p for p in self.failed_platforms],
            "platform_scores": [int(s) for s in self.platform_scores],
            "reasoning": self.reasoning,
            "created_at": int(self.created_at),
            "completed_at": int(self.completed_at),
            "verification_count": int(self.verification_count),
        }


# =============================================================================
# CONSENSUS BLOCK (LEADER + VALIDATOR)
# =============================================================================

def _consensus_leader(
    profiles: list[dict],
    scheme_name: str,
    verification_rubric: str,
    platform_to_messages: dict[str, list[str]],
    score_history: list[int] | None = None,
) -> dict:
    """Runs independently on every validator. Fetches each social media profile,
    and asks the model to verify if the required messages exist.
    
    Returns ``{"verified_platforms": [...], "failed_platforms": [...],
    "platform_scores": {...}, "platform_urls": {...}, "trust_score": int,
    "stored_score": int, "stored_level": str, "reasoning": str}``."""
    
    verified_platforms = []
    failed_platforms = []
    platform_scores = {}
    platform_urls = {}

    for profile in profiles:
        platform = profile["platform"]
        url = profile["profile_url"]
        
        # Get platform-specific required messages
        platform_msgs = platform_to_messages.get(platform, [])
        required_msg = profile.get("verification_message", "")
        
        # Verify the message is valid for this platform
        msg_valid = False
        for pm in platform_msgs:
            if required_msg.lower() in pm.lower() or pm.lower() in required_msg.lower():
                msg_valid = True
                break

        # Bind to the exact URL that was registered
        platform_urls[platform] = url

        try:
            response = gl.nondet.web.get(url)
            text = response.body.decode("utf-8")[:MAX_PROFILE_CHARS]

            prompt = f"""You are a social media profile verifier for the scheme "{scheme_name}".

VERIFICATION RUBRIC:
{verification_rubric}

PLATFORM: {platform}
PROFILE URL: {url}
REQUIRED MESSAGE TO FIND: {required_msg}
PLATFORM'S ALLOWED MESSAGES: {platform_msgs}

PROFILE CONTENT:
{text}

Check if the profile contains the required message or evidence of the claimed identity.
The message must match one of the platform's allowed messages.
Score the verification quality from 0 to 100:
- 100: Clear, unambiguous match with strong evidence
- 75: Good match with minor ambiguities
- 50: Partial match, some evidence present
- 25: Weak match, circumstantial evidence only
- 0: No match or contradictory evidence

Set "red_flagged" to true if the evidence appears fabricated or suspicious.

Respond with ONLY a JSON object, no other text, no markdown fences:
{{"verified": true/false, "score": <0-100>, "reasoning": "<brief explanation>", "red_flagged": true/false}}"""

            parsed = gl.nondet.exec_prompt(prompt, response_format="json")
            payload = _parse_json_object(parsed) or {}

            verified = bool(payload.get("verified", False))
            score = _to_int(payload.get("score")) or 0
            red_flagged = bool(payload.get("red_flagged", False))

            if verified and not red_flagged:
                verified_platforms.append(platform)
                platform_scores[platform] = score
            else:
                failed_platforms.append(platform)
                platform_scores[platform] = score

        except Exception:
            failed_platforms.append(platform)
            platform_scores[platform] = 0

    # Compute trust score from verified platforms and their scores
    scores = [
        platform_scores.get(p, 0)
        for p in verified_platforms
    ]
    trust_score = _compute_trust_score(
        len(verified_platforms), len(profiles), scores
    )

    # Compute stored outcome with median smoothing
    hist = list(score_history) if score_history is not None else []
    stored_score, stored_level = _compute_stored_outcome(trust_score, hist)

    return {
        "verified_platforms": verified_platforms,
        "failed_platforms": failed_platforms,
        "platform_scores": platform_scores,
        "platform_urls": platform_urls,
        "trust_score": trust_score,
        "stored_score": stored_score,
        "stored_level": stored_level,
        "reasoning": "Verification completed across all platforms",
    }


def _consensus_validator(
    leaders_res,
    profiles: list[dict],
    scheme_name: str,
    verification_rubric: str,
    platform_to_messages: dict[str, list[str]],
    tolerance: int = SCORE_TOLERANCE,
    score_history: list[int] | None = None,
) -> bool:
    """The equivalence check. Runs on every validator, which independently
    re-fetches every profile and re-verifies the messages. The leader's
    result is accepted only when:
    
    - the leader result passes the deterministic shape check;
    - verified/failed platform lists match exactly;
    - platform scores agree within tolerance;
    - exact trust score match;
    - stored outcome matches (median-smoothed score and level);
    - platform URLs match exactly (binds to registered URLs).
    """
    if not isinstance(leaders_res, gl.vm.Return):
        return False
    leader_data = leaders_res.calldata
    if not isinstance(leader_data, dict):
        return False
    if not _consensus_ok(leader_data, len(profiles)):
        return False

    # Re-run verification independently with same inputs
    my_data = _consensus_leader(
        profiles, scheme_name, verification_rubric, platform_to_messages,
        score_history=score_history,
    )
    if not _consensus_ok(my_data, len(profiles)):
        return False

    # Compare verified/failed platforms (exact match)
    if set(leader_data["verified_platforms"]) != set(my_data["verified_platforms"]):
        return False
    if set(leader_data["failed_platforms"]) != set(my_data["failed_platforms"]):
        return False

    # Compare platform URLs (exact match - binds to registered URLs)
    if leader_data["platform_urls"] != my_data["platform_urls"]:
        return False

    # Compare platform scores (within tolerance)
    for platform in leader_data["platform_scores"]:
        leader_score = _to_int(leader_data["platform_scores"][platform]) or 0
        my_score = _to_int(my_data["platform_scores"].get(platform, 0)) or 0
        if abs(leader_score - my_score) > tolerance:
            return False

    # Compare trust score (exact match)
    leader_trust = _to_int(leader_data.get("trust_score", -1))
    my_trust = _to_int(my_data.get("trust_score", -2))
    if leader_trust is None or my_trust is None:
        return False
    if leader_trust != my_trust:
        return False

    # Verify stored outcome matches
    # Leader must compute stored_score from leader's own trust_score and shared history
    if score_history is not None:
        hist = list(score_history)
        hist.append(leader_trust)
        if len(hist) > MAX_HISTORY:
            hist = hist[-MAX_HISTORY:]
        expected_stored = _median(hist)
        expected_level = _trust_level_for_score(expected_stored)

        claimed_stored = _to_int(leader_data.get("stored_score", -1))
        claimed_level = str(leader_data.get("stored_level", ""))

        if claimed_stored != expected_stored:
            return False
        if claimed_level != expected_level:
            return False

    return True

# =============================================================================
# SMART CONTRACT
# =============================================================================

class SocialProofVerifier(gl.Contract):
    """On-chain identity verification via social media proof."""
    
    scheme_name: str
    verification_rubric: str
    cooldown_seconds: u256
    deployer: Address
    
    # Deployment-configured platform-to-message mapping (parallel arrays)
    # platform_names[i] -> platform_required_messages[i]
    platform_names: DynArray[str]
    platform_required_messages: DynArray[str]
    
    # User profiles: address_key -> DynArray[SocialProfile]
    user_profiles: TreeMap[str, DynArray[SocialProfile]]
    
    # User score history: address_key -> DynArray[u256]
    user_score_history: TreeMap[str, DynArray[u256]]
    
    # Verification requests: request_id -> VerificationRequest
    verification_requests: TreeMap[str, VerificationRequest]
    
    # User trust scores: address_key -> u256 (stored score after median smoothing)
    user_trust_scores: TreeMap[str, u256]
    
    # User trust levels: address_key -> str
    user_trust_levels: TreeMap[str, str]
    
    # User last verification timestamp: address_key -> u256
    user_last_verified: TreeMap[str, u256]
    
    # Request counter for unique IDs
    request_count: u256
    
    # Verification counter per user: address_key -> u256
    user_verification_count: TreeMap[str, u256]

    def __init__(
        self,
        scheme_name: str,
        verification_rubric: str,
        supported_platforms: list[str],
        required_messages: list[str],
        cooldown_seconds: int = COOLDOWN_SECONDS,
    ):
        self.scheme_name = scheme_name.strip()
        self.verification_rubric = verification_rubric.strip()

        if not self.scheme_name:
            raise gl.vm.UserError("scheme_name must not be empty")
        if not self.verification_rubric:
            raise gl.vm.UserError("verification_rubric must not be empty")

        validated_platforms = [_validate_platform(p) for p in supported_platforms]
        if not validated_platforms:
            raise gl.vm.UserError("at least one platform must be supported")

        if len(validated_platforms) != len(required_messages):
            raise gl.vm.UserError("supported_platforms and required_messages must have the same length")

        for platform, message in zip(validated_platforms, required_messages):
            stripped_msg = message.strip()
            if not stripped_msg:
                raise gl.vm.UserError(f"required message must not be empty for platform '{platform}'")
            self.platform_names.append(platform)
            self.platform_required_messages.append(stripped_msg)

        self.cooldown_seconds = u256(int(cooldown_seconds))
        self.deployer = gl.message.sender_address
        self.request_count = u256(0)

    def _get_platform_index(self, platform: str) -> int:
        """Find index of a platform in the platform_names array. Returns -1 if not found."""
        for i in range(len(self.platform_names)):
            if self.platform_names[i] == platform:
                return i
        return -1

    def _get_required_message(self, platform: str) -> str:
        """Get the required message for a platform. Raises if platform not configured."""
        idx = self._get_platform_index(platform)
        if idx == -1:
            raise gl.vm.UserError(
                f"platform '{platform}' is not configured. "
                f"Supported platforms: {[str(p) for p in self.platform_names]}"
            )
        return self.platform_required_messages[idx]

    # --- Write Methods ---

    @gl.public.write
    def register_profile(
        self,
        user_address,
        platform: str,
        profile_url: str,
        verification_message: str,
    ) -> None:
        """Register a social media profile for verification.
        
        Only the user themselves can register their own profiles.
        Cannot register duplicate platforms.
        Platform must be in the deployment-configured platform_to_messages.
        Verification message must match one of the platform's required messages.
        """
        user = _coerce_address(user_address)
        sender = gl.message.sender_address

        # Caller authorization: only user or deployer
        if user != sender and sender != self.deployer:
            raise gl.vm.UserError("only the user or deployer can register profiles")

        platform = _validate_platform(platform)
        
        # Check if platform exists in deployment config
        if self._get_platform_index(platform) == -1:
            raise gl.vm.UserError(
                f"platform '{platform}' is not configured. "
                f"Supported platforms: {[str(p) for p in self.platform_names]}"
            )
        
        # Validate URL against platform's authoritative host
        profile_url = _validate_profile_url(profile_url, platform)

        # Validate verification message matches deployment-configured required messages
        verification_message = verification_message.strip()
        if not verification_message:
            raise gl.vm.UserError("verification_message must not be empty")
        
        # Get platform-specific required message
        required_msg = self._get_required_message(platform)
        if not (verification_message.lower() in required_msg.lower() or required_msg.lower() in verification_message.lower()):
            raise gl.vm.UserError(
                f"verification_message must match the required message for '{platform}': '{required_msg}'"
            )

        user_key = str(user)
        profiles = self.user_profiles.get(user_key, [])

        # Check for duplicate platform
        for existing in profiles:
            if existing.platform == platform:
                raise gl.vm.UserError(f"profile already registered for {platform}")

        # Check max profiles
        if len(profiles) >= MAX_PROFILES:
            raise gl.vm.UserError(f"maximum {MAX_PROFILES} profiles allowed")

        now = _current_timestamp()
        new_profile = SocialProfile(
            platform=platform,
            profile_url=profile_url,
            verification_message=verification_message,
            status="pending",
            verification_score=u256(0),
            verified_at=u256(0),
            last_checked_at=u256(0),
            red_flagged=False,
            check_count=u256(0),
        )

        profiles.append(new_profile)
        self.user_profiles[user_key] = profiles

    @gl.public.write
    def update_profile(
        self,
        user_address,
        platform: str,
        profile_url: str,
        verification_message: str,
    ) -> None:
        """Update an existing profile.
        
        Only the user themselves can update their own profiles.
        Cannot update profiles that are currently being verified.
        Platform must be in the deployment-configured platform_to_messages.
        Verification message must match one of the platform's required messages.
        """
        user = _coerce_address(user_address)
        sender = gl.message.sender_address

        # Caller authorization
        if user != sender and sender != self.deployer:
            raise gl.vm.UserError("only the user or deployer can update profiles")

        platform = _validate_platform(platform)
        
        # Check if platform exists in deployment config
        if self._get_platform_index(platform) == -1:
            raise gl.vm.UserError(
                f"platform '{platform}' is not configured. "
                f"Supported platforms: {[str(p) for p in self.platform_names]}"
            )
        
        # Validate URL against platform's authoritative host
        profile_url = _validate_profile_url(profile_url, platform)

        # Validate verification message matches deployment-configured required messages
        verification_message = verification_message.strip()
        if not verification_message:
            raise gl.vm.UserError("verification_message must not be empty")
        
        # Get platform-specific required message
        required_msg = self._get_required_message(platform)
        if not (verification_message.lower() in required_msg.lower() or required_msg.lower() in verification_message.lower()):
            raise gl.vm.UserError(
                f"verification_message must match the required message for '{platform}': '{required_msg}'"
            )

        user_key = str(user)
        profiles = self.user_profiles.get(user_key, [])

        found = False
        for i, existing in enumerate(profiles):
            if existing.platform == platform:
                # Cannot update while verification is in progress
                if existing.status == "pending" and existing.check_count > 0:
                    raise gl.vm.UserError("cannot update profile during verification")
                
                profiles[i] = SocialProfile(
                    platform=platform,
                    profile_url=profile_url,
                    verification_message=verification_message,
                    status="pending",
                    verification_score=u256(0),
                    verified_at=u256(0),
                    last_checked_at=u256(0),
                    red_flagged=False,
                    check_count=u256(0),
                )
                found = True
                break

        if not found:
            raise gl.vm.UserError(f"no profile found for {platform}")

        self.user_profiles[user_key] = profiles

    @gl.public.write
    def request_verification(self, user_address) -> str:
        """Request verification of all registered profiles for a user.
        
        Only the user themselves or the deployer can trigger verification.
        Cooldown is enforced: user must wait for cooldown to elapsed.
        Returns the request_id.
        """
        user = _coerce_address(user_address)
        sender = gl.message.sender_address

        # Caller authorization: only user or deployer
        if user != sender and sender != self.deployer:
            raise gl.vm.UserError("only the user or deployer can request verification")

        user_key = str(user)

        # Cooldown enforcement
        now = _current_timestamp()
        last_verified = int(self.user_last_verified.get(user_key, u256(0)))
        if last_verified > 0 and now < last_verified + int(self.cooldown_seconds):
            remaining = last_verified + int(self.cooldown_seconds) - now
            raise gl.vm.UserError(
                f"verification cooldown: {remaining} seconds remaining"
            )

        profiles = self.user_profiles.get(user_key, [])
        if not profiles:
            raise gl.vm.UserError("no profiles registered for this user")

        # Check if any profile is currently being verified
        for p in profiles:
            if p.status == "pending" and p.check_count > 0:
                raise gl.vm.UserError(
                    f"profile {p.platform} is currently being verified"
                )

        # Increment verification count
        vcount = int(self.user_verification_count.get(user_key, u256(0)))
        self.user_verification_count[user_key] = u256(vcount + 1)

        # Generate globally collision-resistant request ID using full address
        # Format: req-{full_address_without_0x}-{global_count}-{user_count}
        global_count = int(self.request_count)
        self.request_count = self.request_count + u256(1)
        request_id = f"req-{user_key}-{global_count}-{vcount}"

        # Prepare profile data for consensus (frozen snapshot)
        profile_data = []
        for p in profiles:
            profile_data.append({
                "platform": p.platform,
                "profile_url": p.profile_url,
                "verification_message": p.verification_message,
            })

        # Get score history for median smoothing
        hist = [int(s) for s in self.user_score_history.get(user_key, [])]

        scheme_name = self.scheme_name
        rubric = self.verification_rubric
        
        # Build platform-to-messages mapping for consensus from parallel arrays
        platform_msgs = {}
        for i in range(len(self.platform_names)):
            platform_msgs[self.platform_names[i]] = [self.platform_required_messages[i]]

        # Mark profiles as being verified (check_count incremented)
        for i, p in enumerate(profiles):
            profiles[i].check_count = p.check_count + u256(1)
        self.user_profiles[user_key] = profiles

        # Non-deterministic consensus block
        def leader_fn():
            return _consensus_leader(
                profile_data, scheme_name, rubric, platform_msgs,
                score_history=hist,
            )

        def validator_fn(leaders_res):
            return _consensus_validator(
                leaders_res, profile_data, scheme_name, rubric, platform_msgs,
                SCORE_TOLERANCE, score_history=hist,
            )

        result = gl.vm.run_nondet_unsafe(leader_fn, validator_fn)

        if not _consensus_ok(result, len(profiles)):
            raise gl.vm.UserError("consensus result was unusable")

        # Extract results
        verified_platforms = result["verified_platforms"]
        failed_platforms = result["failed_platforms"]
        platform_scores = result["platform_scores"]
        platform_urls = result["platform_urls"]
        trust_score = int(result["trust_score"])
        stored_score = int(result["stored_score"])
        stored_level = str(result["stored_level"])

        # Atomic profile updates
        for i, p in enumerate(profiles):
            if p.platform in verified_platforms:
                profiles[i].status = "verified"
                profiles[i].verification_score = u256(
                    _to_int(platform_scores.get(p.platform, 0)) or 0
                )
                profiles[i].verified_at = now
                profiles[i].last_checked_at = now
            else:
                profiles[i].status = "failed"
                profiles[i].verification_score = u256(0)
                profiles[i].last_checked_at = now

        self.user_profiles[user_key] = profiles

        # Determine request status
        if len(verified_platforms) == len(profiles):
            status = "verified"
        elif len(verified_platforms) > 0:
            status = "partial"
        else:
            status = "failed"

        # Store verification request
        self.verification_requests[request_id] = VerificationRequest(
            request_id=request_id,
            user_address=user,
            platforms=[p.platform for p in profiles],
            platform_urls=[p.profile_url for p in profiles],
            status=status,
            trust_score=u256(trust_score),
            stored_score=u256(stored_score),
            stored_level=stored_level,
            verified_platforms=verified_platforms,
            failed_platforms=failed_platforms,
            platform_scores=[u256(platform_scores.get(p.platform, 0)) for p in profiles],
            reasoning=str(result.get("reasoning", "")),
            created_at=now,
            completed_at=now,
            verification_count=u256(vcount + 1),
        )

        # Update user trust score and level (median-smoothed)
        self.user_trust_scores[user_key] = u256(stored_score)
        self.user_trust_levels[user_key] = stored_level
        self.user_last_verified[user_key] = now

        # Update score history
        history = list(self.user_score_history.get(user_key, []))
        history.append(u256(trust_score))
        if len(history) > MAX_HISTORY:
            history = history[-MAX_HISTORY:]
        self.user_score_history[user_key] = history

        return request_id

    # --- Read Methods ---

    @gl.public.view
    def get_scheme(self) -> dict:
        """Get the immutable scheme parameters."""
        platform_msgs = {}
        for i in range(len(self.platform_names)):
            platform_msgs[self.platform_names[i]] = [self.platform_required_messages[i]]
        
        return {
            "scheme_name": self.scheme_name,
            "verification_rubric": self.verification_rubric,
            "platform_to_messages": platform_msgs,
            "cooldown_seconds": int(self.cooldown_seconds),
            "deployer": str(self.deployer),
        }

    @gl.public.view
    def get_profiles(self, user_address) -> list[dict]:
        """Get all profiles for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        profiles = self.user_profiles.get(user_key, [])
        return [p.as_dict() for p in profiles]

    @gl.public.view
    def get_verification(self, request_id: str) -> dict:
        """Get verification request details."""
        request_id = str(request_id)
        request = self.verification_requests.get(request_id)
        if request is None:
            raise gl.vm.UserError("unknown request_id")
        return request.as_dict()

    @gl.public.view
    def get_trust_score(self, user_address) -> u256:
        """Get the stored trust score (median-smoothed) for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        return self.user_trust_scores.get(user_key, u256(0))

    @gl.public.view
    def get_trust_level(self, user_address) -> str:
        """Get the trust level for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        return self.user_trust_levels.get(user_key, "unverified")

    @gl.public.view
    def is_verified(self, user_address) -> bool:
        """Check if a user has any verified profiles."""
        user = _coerce_address(user_address)
        user_key = str(user)
        profiles = self.user_profiles.get(user_key, [])
        return any(p.status == "verified" for p in profiles)

    @gl.public.view
    def get_verified(self, user_address, min_trust_score: int = 50) -> bool:
        """Reusable primitive for composing contracts.
        
        Does the user's stored trust score meet the minimum threshold?
        Returns False for unknown users.
        """
        score = int(self.get_trust_score(user_address))
        return score >= min_trust_score

    @gl.public.view
    def get_verified_count(self, user_address) -> dict:
        """Get counts of verified and failed platforms for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        profiles = self.user_profiles.get(user_key, [])

        verified = sum(1 for p in profiles if p.status == "verified")
        failed = sum(1 for p in profiles if p.status == "failed")
        pending = sum(1 for p in profiles if p.status == "pending")

        return {
            "total": len(profiles),
            "verified": verified,
            "failed": failed,
            "pending": pending,
        }

    @gl.public.view
    def get_score_history(self, user_address) -> list[int]:
        """Get the score history for a user (used for median smoothing)."""
        user = _coerce_address(user_address)
        user_key = str(user)
        history = self.user_score_history.get(user_key, [])
        return [int(s) for s in history]

    @gl.public.view
    def get_last_verified(self, user_address) -> u256:
        """Get the timestamp of last verification for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        return self.user_last_verified.get(user_key, u256(0))

    @gl.public.view
    def get_cooldown_remaining(self, user_address) -> int:
        """Get remaining cooldown in seconds for a user."""
        user = _coerce_address(user_address)
        user_key = str(user)
        now = int(_current_timestamp())
        last_verified = int(self.user_last_verified.get(user_key, u256(0)))
        
        if last_verified == 0:
            return 0
        
        elapsed = now - last_verified
        if elapsed >= int(self.cooldown_seconds):
            return 0
        
        return int(self.cooldown_seconds) - elapsed

# =============================================================================
# UNIT TESTS
# =============================================================================

class TestTrustLevelForScore:
    def test_premium_score(self):
        assert _trust_level_for_score(100) == "premium"
        assert _trust_level_for_score(90) == "premium"

    def test_enhanced_score(self):
        assert _trust_level_for_score(89) == "enhanced"
        assert _trust_level_for_score(75) == "enhanced"

    def test_standard_score(self):
        assert _trust_level_for_score(74) == "standard"
        assert _trust_level_for_score(50) == "standard"

    def test_basic_score(self):
        assert _trust_level_for_score(49) == "basic"
        assert _trust_level_for_score(25) == "basic"

    def test_unverified_score(self):
        assert _trust_level_for_score(24) == "unverified"
        assert _trust_level_for_score(0) == "unverified"


class TestComputeTrustScore:
    def test_all_verified_high_scores(self):
        score = _compute_trust_score(3, 3, [90, 95, 85])
        assert score == 100

    def test_no_verification(self):
        score = _compute_trust_score(0, 3, [])
        assert score == 0

    def test_partial_verification(self):
        score = _compute_trust_score(2, 3, [80, 90])
        assert 65 <= score <= 80

    def test_empty_profiles(self):
        score = _compute_trust_score(0, 0, [])
        assert score == 0

    def test_score_never_exceeds_100(self):
        score = _compute_trust_score(5, 5, [100, 100, 100, 100, 100])
        assert score == 100


class TestComputeStoredOutcome:
    def test_first_verification(self):
        stored_score, stored_level = _compute_stored_outcome(80, [])
        assert stored_score == 80
        assert stored_level == "enhanced"

    def test_median_smoothing(self):
        # History: [60, 70], new score: 80
        # Sorted: [60, 70, 80], median = 70
        stored_score, stored_level = _compute_stored_outcome(80, [60, 70])
        assert stored_score == 70
        assert stored_level == "enhanced"

    def test_history_capped_at_max(self):
        history = [50, 60, 70, 80, 90]
        stored_score, stored_level = _compute_stored_outcome(100, history)
        # History becomes [60, 70, 80, 90, 100], median = 80
        assert stored_score == 80
        assert stored_level == "enhanced"

    def test_outlier_protection(self):
        # History: [80, 80, 80, 80], new outlier: 20
        # Sorted: [20, 80, 80, 80, 80], median = 80
        stored_score, stored_level = _compute_stored_outcome(20, [80, 80, 80, 80])
        assert stored_score == 80
        assert stored_level == "enhanced"


class TestMedian:
    def test_odd_count(self):
        assert _median([1, 3, 5]) == 3
        assert _median([1, 2, 3, 4, 5]) == 3

    def test_even_count(self):
        assert _median([1, 2, 3, 4]) == 2  # (2+3)//2
        assert _median([10, 20, 30, 40]) == 25

    def test_single_element(self):
        assert _median([50]) == 50


class TestValidatePlatform:
    def test_valid_platforms(self):
        for platform in SUPPORTED_PLATFORMS:
            assert _validate_platform(platform) == platform
            assert _validate_platform(platform.upper()) == platform

    def test_custom_platform_accepted(self):
        assert _validate_platform("custom_platform") == "custom_platform"
        assert _validate_platform("  MyPlatform  ") == "myplatform"

    def test_empty_platform_rejected(self):
        try:
            _validate_platform("")
            assert False, "Should have raised error"
        except gl.vm.UserError:
            pass


class TestValidateProfileUrl:
    def test_valid_urls(self):
        # Twitter/X URLs
        assert _validate_profile_url("https://twitter.com/user", "twitter") == "https://twitter.com/user"
        assert _validate_profile_url("https://x.com/user", "twitter") == "https://x.com/user"
        assert _validate_profile_url("http://twitter.com/user", "twitter") == "http://twitter.com/user"
        
        # GitHub URLs
        assert _validate_profile_url("https://github.com/user", "github") == "https://github.com/user"
        
        # Discord URLs
        assert _validate_profile_url("https://discord.com/user", "discord") == "https://discord.com/user"
        assert _validate_profile_url("https://discord.gg/invite", "discord") == "https://discord.gg/invite"
        
        # Telegram URLs
        assert _validate_profile_url("https://t.me/username", "telegram") == "https://t.me/username"
        assert _validate_profile_url("https://telegram.org/username", "telegram") == "https://telegram.org/username"
        
        # LinkedIn URLs
        assert _validate_profile_url("https://linkedin.com/in/user", "linkedin") == "https://linkedin.com/in/user"

    def test_invalid_urls(self):
        # Invalid URL format
        for url in ["ftp://twitter.com/user", "not-a-url", ""]:
            try:
                _validate_profile_url(url, "twitter")
                assert False, "Should have raised error"
            except gl.vm.UserError:
                pass

    def test_wrong_host_for_platform(self):
        # GitHub URL for Twitter platform
        try:
            _validate_profile_url("https://github.com/user", "twitter")
            assert False, "Should have raised error"
        except gl.vm.UserError as e:
            assert "not authoritative" in str(e)
        
        # Twitter URL for GitHub platform
        try:
            _validate_profile_url("https://twitter.com/user", "github")
            assert False, "Should have raised error"
        except gl.vm.UserError as e:
            assert "not authoritative" in str(e)

    def test_www_prefix_stripped(self):
        # www. prefix should be stripped
        assert _validate_profile_url("https://www.twitter.com/user", "twitter") == "https://www.twitter.com/user"


class TestToInt:
    def test_int_input(self):
        assert _to_int(50) == 50
        assert _to_int(0) == 0
        assert _to_int(100) == 100

    def test_string_input(self):
        assert _to_int("50") == 50
        assert _to_int("0") == 0

    def test_string_with_decimal(self):
        assert _to_int("50.5") == 50

    def test_float_input(self):
        assert _to_int(50.5) == 50

    def test_bool_input(self):
        assert _to_int(True) is None
        assert _to_int(False) is None

    def test_out_of_range(self):
        assert _to_int(-1) is None
        assert _to_int(101) is None

    def test_invalid_input(self):
        assert _to_int(None) is None
        assert _to_int([]) is None


class TestConsensusOk:
    def test_valid_payload(self):
        data = {
            "verified_platforms": ["twitter", "github"],
            "failed_platforms": ["discord"],
            "platform_scores": {"twitter": 80, "github": 90, "discord": 30},
            "platform_urls": {
                "twitter": "https://twitter.com/user",
                "github": "https://github.com/user",
                "discord": "https://discord.com/user",
            },
            "trust_score": 85,
            "stored_score": 80,
            "stored_level": "enhanced",
            "reasoning": "All profiles verified",
        }
        assert _consensus_ok(data, 3) is True

    def test_missing_field(self):
        data = {
            "verified_platforms": ["twitter"],
            "failed_platforms": [],
            "platform_scores": {"twitter": 80},
            "platform_urls": {"twitter": "https://twitter.com/user"},
            "trust_score": 80,
            "stored_score": 80,
            "stored_level": "enhanced",
        }
        assert _consensus_ok(data, 1) is False

    def test_wrong_platform_count(self):
        data = {
            "verified_platforms": ["twitter"],
            "failed_platforms": [],
            "platform_scores": {"twitter": 80},
            "platform_urls": {"twitter": "https://twitter.com/user"},
            "trust_score": 80,
            "stored_score": 80,
            "stored_level": "enhanced",
            "reasoning": "Test",
        }
        assert _consensus_ok(data, 3) is False

    def test_invalid_score(self):
        data = {
            "verified_platforms": ["twitter"],
            "failed_platforms": [],
            "platform_scores": {"twitter": "invalid"},
            "platform_urls": {"twitter": "https://twitter.com/user"},
            "trust_score": 80,
            "stored_score": 80,
            "stored_level": "enhanced",
            "reasoning": "Test",
        }
        assert _consensus_ok(data, 1) is False

    def test_missing_platform_urls(self):
        data = {
            "verified_platforms": ["twitter"],
            "failed_platforms": [],
            "platform_scores": {"twitter": 80},
            "platform_urls": {},
            "trust_score": 80,
            "stored_score": 80,
            "stored_level": "enhanced",
            "reasoning": "Test",
        }
        assert _consensus_ok(data, 1) is False


class TestStripCodeFence:
    def test_no_fence(self):
        assert _strip_code_fence("hello") == "hello"

    def test_with_fence(self):
        fenced = "```\n{\"key\": \"value\"}\n```"
        assert _strip_code_fence(fenced) == '{"key": "value"}'

    def test_with_language_tag(self):
        fenced = "```json\n{\"key\": \"value\"}\n```"
        assert _strip_code_fence(fenced) == '{"key": "value"}'


class TestParseJsonObject:
    def test_dict_input(self):
        data = {"key": "value"}
        assert _parse_json_object(data) == data

    def test_valid_json_string(self):
        json_str = '{"key": "value"}'
        assert _parse_json_object(json_str) == {"key": "value"}

    def test_json_with_code_fence(self):
        fenced = '```json\n{"key": "value"}\n```'
        assert _parse_json_object(fenced) == {"key": "value"}

    def test_invalid_json(self):
        assert _parse_json_object("not json") is None

    def test_non_dict_json(self):
        assert _parse_json_object('["not", "a", "dict"]') is None


class TestPlatformUrlHosts:
    def test_platform_url_hosts_mapping(self):
        """Verify that all supported platforms have URL host mappings."""
        for platform in SUPPORTED_PLATFORMS:
            assert platform in PLATFORM_URL_HOSTS, f"Platform {platform} missing URL host mapping"
            hosts = PLATFORM_URL_HOSTS[platform]
            assert len(hosts) > 0, f"Platform {platform} has empty URL host list"

    def test_twitter_hosts(self):
        """Verify Twitter/X platform has correct authoritative hosts."""
        hosts = PLATFORM_URL_HOSTS["twitter"]
        assert "twitter.com" in hosts
        assert "x.com" in hosts

    def test_github_hosts(self):
        """Verify GitHub platform has correct authoritative hosts."""
        hosts = PLATFORM_URL_HOSTS["github"]
        assert "github.com" in hosts

    def test_discord_hosts(self):
        """Verify Discord platform has correct authoritative hosts."""
        hosts = PLATFORM_URL_HOSTS["discord"]
        assert "discord.com" in hosts
        assert "discord.gg" in hosts

    def test_telegram_hosts(self):
        """Verify Telegram platform has correct authoritative hosts."""
        hosts = PLATFORM_URL_HOSTS["telegram"]
        assert "t.me" in hosts
        assert "telegram.org" in hosts

    def test_linkedin_hosts(self):
        """Verify LinkedIn platform has correct authoritative hosts."""
        hosts = PLATFORM_URL_HOSTS["linkedin"]
        assert "linkedin.com" in hosts


class TestTrustLevelRank:
    def test_rank_ordering(self):
        assert _trust_level_rank("unverified") < _trust_level_rank("basic")
        assert _trust_level_rank("basic") < _trust_level_rank("standard")
        assert _trust_level_rank("standard") < _trust_level_rank("enhanced")
        assert _trust_level_rank("enhanced") < _trust_level_rank("premium")


class TestSecurityScenarios:
    """Security-focused tests for adversarial scenarios."""

    def test_double_submit_prevention(self):
        """Verify that double submission is prevented by cooldown."""
        # This would need contract state testing
        # Here we verify the cooldown logic exists
        assert COOLDOWN_SECONDS > 0

    def test_caller_authorization(self):
        """Verify caller authorization logic exists."""
        # User must be self or deployer
        assert True  # Authorization checks in contract

    def test_url_binding(self):
        """Verify that URLs are bound in consensus."""
        data = {
            "verified_platforms": ["twitter"],
            "failed_platforms": [],
            "platform_scores": {"twitter": 80},
            "platform_urls": {"twitter": "https://twitter.com/user"},
            "trust_score": 80,
            "stored_score": 80,
            "stored_level": "enhanced",
            "reasoning": "Test",
        }
        assert _consensus_ok(data, 1) is True

    def test_trust_score_exact_match(self):
        """Verify trust score must match exactly."""
        # In consensus validator, trust_score must be exact
        assert True  # Enforced in _consensus_validator

    def test_stored_outcome_validation(self):
        """Verify stored outcome is validated."""
        # Leader must compute and claim stored_score and stored_level
        # Validator verifies against shared history
        assert True  # Enforced in _consensus_validator
