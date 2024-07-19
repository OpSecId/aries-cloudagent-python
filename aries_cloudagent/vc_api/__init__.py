from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from ..core.profile import Profile


async def setup(context: InjectionContext):
    """Setup vc-api plugin."""
    from .services import IssuerService, VerifierService, StatusService

    context.injector.bind_provider(
        IssuerService, ClassProvider(IssuerService, ClassProvider.Inject(Profile))
    )
    context.injector.bind_provider(
        VerifierService, ClassProvider(VerifierService, ClassProvider.Inject(Profile))
    )
    context.injector.bind_provider(
        StatusService, ClassProvider(StatusService, ClassProvider.Inject(Profile))
    )
