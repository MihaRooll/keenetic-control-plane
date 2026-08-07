"""Shared typed operation executor — identical policy for certification and runtime."""



from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.adapters.netcraze.codec import (
    CodecError,
    ContinuationToken,
    Exchange,
    HttpExchange,
    NormalizedError,
    OperationCodec,
    SealedCliExchange,
    SecretResolver,
    TypedIntent,
    TypedOutcome,
    WireRequest,
    codec_for_spec,
)
from router_control.adapters.netcraze.operation_spec import (
    OperationSpec,
    OperationSpecError,
    RegisteredOperation,
    RetryPolicy,
    TransportKind,
)
from router_control.adapters.netcraze.shape_registry import (
    CertifiedOperationRegistry,
    ShapePromotionState,
)

_MAX_CONTINUATION_ROUNDS = 5

_VERIFIED_STATUSES = frozenset(

    {

        "ok",

        "executed",

        "passed",

        "verified",

        "import_verified",

        "read_back_verified",

        "handshake_verified",

        "reachability_verified",

    }

)





class ExecutorError(OperationSpecError):

    """Executor policy or transport failure."""





class ExecutionContextKind(StrEnum):

    CERTIFICATION = "certification"

    RUNTIME = "runtime"





@dataclass(frozen=True, slots=True)

class ExecutionInstrumentation:

    context_kind: ExecutionContextKind

    spec_digest: str

    codec_digest: str

    executor_digest: str

    wire_request_digest: str

    continuation_rounds: int = 0



    def sanitized_dict(self) -> dict[str, str | int]:

        return {

            "context_kind": self.context_kind.value,

            "spec_digest": self.spec_digest,

            "codec_digest": self.codec_digest,

            "executor_digest": self.executor_digest,

            "wire_request_digest": self.wire_request_digest,

            "continuation_rounds": self.continuation_rounds,

        }



    def parity_matches(self, other: ExecutionInstrumentation) -> bool:

        return (

            self.spec_digest == other.spec_digest

            and self.codec_digest == other.codec_digest

            and self.executor_digest == other.executor_digest

        )





@dataclass(frozen=True, slots=True)

class ExecutionResult:

    outcome: TypedOutcome | None

    error: NormalizedError | None

    instrumentation: ExecutionInstrumentation

    sanitized: dict[str, Any]



    @property

    def passed(self) -> bool:

        if self.error is not None or self.outcome is None:

            return False

        return self.outcome.status.lower() in _VERIFIED_STATUSES





class HttpTransportPort(Protocol):

    def execute_wire(self, request: WireRequest) -> HttpExchange: ...



    def poll_continuation(self, *, token: ContinuationToken) -> HttpExchange: ...





class SealedCliTransportPort(Protocol):

    def execute_sealed(self, request: WireRequest, *, password: str) -> SealedCliExchange: ...



    def is_active(self) -> bool: ...





@dataclass(frozen=True, slots=True)
class LiveMutationPolicy:
    allowed_operation: str
    certified_registry_digest: str
    p1_effect_context_id: str
    t4_contract_id: str
    gate_b_write_certified: bool
    gate_c_open: bool
    gate_d_closed: bool

    def validate(
        self,
        *,
        operation: str,
        registry_digest: str,
        p1_effect_context_id: str,
    ) -> None:
        if operation != self.allowed_operation:
            raise ExecutorError("live mutation operation not permitted by policy")
        if registry_digest != self.certified_registry_digest:
            raise ExecutorError("certified registry digest mismatch")
        if p1_effect_context_id != self.p1_effect_context_id:
            raise ExecutorError("P1 effect context mismatch")
        if not self.gate_b_write_certified:
            raise ExecutorError("Gate B WriteCertified not active")
        if not self.gate_c_open:
            raise ExecutorError("Gate C lab window not open")
        if not self.gate_d_closed:
            raise ExecutorError("Gate D must remain closed")


@dataclass(frozen=True, slots=True)
class CertificationExecutionContext:

    gate_a_open: bool

    gate_c_open: bool

    candidate_spec_digest: str

    trial_authorized: bool

    probe_tuple_match: bool

    gate_d_closed: bool = True

    lab_observed_grant_digest: str = ""

    readback_evidence: bool = False

    functional_evidence: bool = False

    compensation_evidence: bool = False

    dry_run: bool = False

    mock_transport: bool = False

    no_transport: bool = False



    def validate(self) -> None:

        if self.dry_run or self.mock_transport or self.no_transport:

            raise ExecutorError("dry-run/mock/no-transport cannot emit pass")

        if not self.trial_authorized:

            raise ExecutorError("certification requires Gate B/C trial authorization")

        if not self.gate_a_open:

            raise ExecutorError("Gate A ReadOnlyCertified is not open")

        if not self.gate_c_open:

            raise ExecutorError("Gate C lab window is not open")

        if not self.gate_d_closed:

            raise ExecutorError("Gate D must remain closed")

        if not self.probe_tuple_match:

            raise ExecutorError("probe tuple mismatch")

        if not self.candidate_spec_digest:

            raise ExecutorError("candidate spec digest required")

        if not self.lab_observed_grant_digest.strip():

            raise ExecutorError("lab_observed grant digest required")

        if not self.readback_evidence:

            raise ExecutorError("readback evidence required")

        if not self.functional_evidence:

            raise ExecutorError("functional evidence required")

        if not self.compensation_evidence:

            raise ExecutorError("compensation evidence required")





@dataclass(frozen=True, slots=True)

class RuntimeExecutionContext:

    write_certified: bool

    gate_c_applicable: bool

    gate_c_open: bool

    probe_tuple_match: bool

    gate_d_closed: bool | None = None

    dry_run: bool = False

    mock_transport: bool = False

    no_transport: bool = False



    def validate(self) -> None:

        if self.dry_run or self.mock_transport or self.no_transport:

            raise ExecutorError("dry-run/mock/no-transport cannot emit pass")

        if not self.write_certified:

            raise ExecutorError("runtime requires WriteCertified family state")

        if self.gate_c_applicable and not self.gate_c_open:

            raise ExecutorError("Gate C window required but not open")

        if self.gate_d_closed is None:

            raise ExecutorError("Gate D state is required")

        if not self.gate_d_closed:

            raise ExecutorError("Gate D must remain closed")

        if not self.probe_tuple_match:

            raise ExecutorError("probe tuple mismatch")





@dataclass

class SharedTypedOperationExecutor:

    registry: CertifiedOperationRegistry = field(default_factory=CertifiedOperationRegistry)

    executor_version: str = "shared-typed-executor-v1"



    @property

    def executor_digest(self) -> str:

        from router_control.adapters.netcraze.operation_spec import (
            SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN,
        )



        return SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.executor_digest



    def resolve_registered(

        self,

        *,

        family: str,

        operation_id: str,

    ) -> RegisteredOperation:

        return self.registry.get_registered(family, operation_id)



    def execute_certification(

        self,

        registered: RegisteredOperation,

        *,

        intent: TypedIntent,

        context: CertificationExecutionContext,

        secret_resolver: SecretResolver,

        http_transport: HttpTransportPort | None = None,

        cli_transport: SealedCliTransportPort | None = None,

        password: str | None = None,

        profile_digest: str | None = None,

    ) -> ExecutionResult:

        context.validate()

        if registered.promotion_state != ShapePromotionState.LAB_OBSERVED.value:

            raise ExecutorError("certification requires lab_observed promotion state")

        if context.lab_observed_grant_digest != registered.evidence_digest:

            raise ExecutorError("lab_observed grant digest mismatch")

        if intent.operation_spec_digest != registered.spec.spec_digest:

            raise ExecutorError("registered operation spec digest mismatch")

        if context.candidate_spec_digest != registered.spec.spec_digest:

            raise ExecutorError("candidate spec digest mismatch")

        return self._execute(

            registered=registered,

            intent=intent,

            context_kind=ExecutionContextKind.CERTIFICATION,

            secret_resolver=secret_resolver,

            http_transport=http_transport,

            cli_transport=cli_transport,

            password=password,

            profile_digest=profile_digest,

        )



    def execute_runtime(

        self,

        *,

        family: str,

        operation_id: str,

        intent: TypedIntent,

        context: RuntimeExecutionContext,

        secret_resolver: SecretResolver,

        http_transport: HttpTransportPort | None = None,

        cli_transport: SealedCliTransportPort | None = None,

        password: str | None = None,

    ) -> ExecutionResult:

        context.validate()

        registered = self.registry.get_registered(family, operation_id)

        if registered.promotion_state != ShapePromotionState.CERTIFIED.value:

            raise ExecutorError("runtime requires certified promotion state")

        if intent.operation_spec_digest != registered.spec.spec_digest:

            raise ExecutorError("registered operation spec digest mismatch")

        return self._execute(

            registered=registered,

            intent=intent,

            context_kind=ExecutionContextKind.RUNTIME,

            secret_resolver=secret_resolver,

            http_transport=http_transport,

            cli_transport=cli_transport,

            password=password,

            profile_digest=None,

        )



    def _execute(

        self,

        *,

        registered: RegisteredOperation,

        intent: TypedIntent,

        context_kind: ExecutionContextKind,

        secret_resolver: SecretResolver,

        http_transport: HttpTransportPort | None,

        cli_transport: SealedCliTransportPort | None,

        password: str | None,

        profile_digest: str | None,

    ) -> ExecutionResult:

        spec = registered.spec

        if spec.executor_version != self.executor_version:

            raise ExecutorError("executor version mismatch")

        codec = codec_for_spec(spec)

        try:

            wire = codec.encode(intent, secret_resolver)

        except CodecError as exc:

            raise ExecutorError(str(exc)) from exc



        decoded, continuation_rounds = self._dispatch_with_continuation(

            spec=spec,

            codec=codec,

            wire=wire,

            http_transport=http_transport,

            cli_transport=cli_transport,

            password=password,

        )

        wire_digest = wire.sanitized_dict()["body_sha256"]

        instrumentation = ExecutionInstrumentation(

            context_kind=context_kind,

            spec_digest=spec.spec_digest,

            codec_digest=spec.codec_digest,

            executor_digest=spec.executor_digest,

            wire_request_digest=wire_digest,

            continuation_rounds=continuation_rounds,

        )

        sanitized: dict[str, Any] = {

            "operation_id": spec.operation_id,

            "family": spec.family.value,

            "instrumentation": instrumentation.sanitized_dict(),

            "bundle_digests": registered.bundle_digests(),

            "initial_mutation_replayed": False,

        }

        if profile_digest is not None and spec.operation_id == "awg_import":

            sanitized["profile_encoding_used"] = True

            sanitized["profile_digest"] = profile_digest

        if isinstance(decoded, NormalizedError):

            sanitized["error"] = decoded.sanitized_dict()

            return ExecutionResult(

                outcome=None,

                error=decoded,

                instrumentation=instrumentation,

                sanitized=sanitized,

            )

        sanitized["outcome"] = decoded.sanitized_dict()

        sanitized["status"] = decoded.status

        if spec.operation_id == "awg_field_parity_readback":

            sanitized["read_back_verified"] = decoded.status == "read_back_verified"

        if spec.operation_id == "handshake_observe":

            sanitized["handshake_verified"] = decoded.status == "handshake_verified"

        if spec.operation_id == "application_reachability_observe":

            sanitized["application_reachability_verified"] = (

                decoded.status == "reachability_verified"

            )

        return ExecutionResult(

            outcome=decoded,

            error=None,

            instrumentation=instrumentation,

            sanitized=sanitized,

        )



    def _dispatch_with_continuation(

        self,

        *,

        spec: OperationSpec,

        codec: OperationCodec,

        wire: WireRequest,

        http_transport: HttpTransportPort | None,

        cli_transport: SealedCliTransportPort | None,

        password: str | None,

    ) -> tuple[TypedOutcome | NormalizedError, int]:

        exchange = self._dispatch(

            spec=spec,

            wire=wire,

            http_transport=http_transport,

            cli_transport=cli_transport,

            password=password,

        )

        decoded = codec.decode(exchange)

        if isinstance(decoded, NormalizedError):

            return decoded, 0

        if (

            spec.retry_policy != RetryPolicy.CONTINUATION_POLL

            or decoded.continuation is None

            or spec.transport_kind != TransportKind.RCI_HTTP

        ):

            return decoded, 0

        if http_transport is None:

            return NormalizedError(

                error_code="continuation_unsupported",

                message="continuation poll requires HTTP transport",

            ), 0



        prior = decoded.continuation

        rounds = 0

        while prior is not None and rounds < _MAX_CONTINUATION_ROUNDS:

            rounds += 1

            poll_exchange = http_transport.poll_continuation(token=prior)

            if poll_exchange.status == 401:

                return NormalizedError(

                    error_code="session_loss",

                    message="continuation poll session lost",

                ), rounds

            if poll_exchange.status in {408, 504}:

                return NormalizedError(error_code="timeout", message="request timed out"), rounds

            poll_decoded = codec.decode_continuation(poll_exchange, prior_token=prior)

            if isinstance(poll_decoded, NormalizedError):

                return poll_decoded, rounds

            if poll_decoded.continuation is None:

                return poll_decoded, rounds

            prior = poll_decoded.continuation

        return NormalizedError(

            error_code="continuation_exhausted",

            message="continuation max rounds exceeded",

        ), rounds



    def _dispatch(

        self,

        *,

        spec: OperationSpec,

        wire: WireRequest,

        http_transport: HttpTransportPort | None,

        cli_transport: SealedCliTransportPort | None,

        password: str | None,

    ) -> Exchange:

        if spec.transport_kind == TransportKind.RCI_HTTP:

            if http_transport is None:

                raise ExecutorError("active HTTP transport required")

            return http_transport.execute_wire(wire)

        if spec.transport_kind == TransportKind.SEALED_SSH_CLI:

            if cli_transport is None or not cli_transport.is_active():

                raise ExecutorError("active sealed SSH transport required")

            if not password:

                raise ExecutorError("password required for sealed CLI transport")

            return cli_transport.execute_sealed(wire, password=password)

        raise ExecutorError(f"unsupported transport kind: {spec.transport_kind}")





def assert_identical_executor_digests(

    certification: ExecutionInstrumentation,

    runtime: ExecutionInstrumentation,

) -> None:

    if not certification.parity_matches(runtime):

        raise ExecutorError("certification/runtime executor digest parity mismatch")





__all__ = [

    "CertificationExecutionContext",

    "ExecutionContextKind",

    "ExecutionInstrumentation",

    "ExecutionResult",

    "ExecutorError",

    "HttpTransportPort",

    "LiveMutationPolicy",

    "RuntimeExecutionContext",

    "SealedCliTransportPort",

    "SharedTypedOperationExecutor",

    "assert_identical_executor_digests",

]


