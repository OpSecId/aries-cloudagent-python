from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from ..core.profile import Profile


async def setup(context: InjectionContext):
    """Setup vc plugin."""
    from .services import StatusService, IssuerService, VerifierService, HolderService

    context.injector.bind_provider(
        StatusService, ClassProvider(StatusService, ClassProvider.Inject(Profile))
    )

    context.injector.bind_provider(
        IssuerService, ClassProvider(IssuerService, ClassProvider.Inject(Profile))
    )

    context.injector.bind_provider(
        VerifierService, ClassProvider(VerifierService, ClassProvider.Inject(Profile))
    )

    context.injector.bind_provider(
        HolderService, ClassProvider(HolderService, ClassProvider.Inject(Profile))
    )
