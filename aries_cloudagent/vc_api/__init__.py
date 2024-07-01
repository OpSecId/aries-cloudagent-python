from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from ..core.profile import Profile


async def setup(context: InjectionContext):
    """Setup vc-api plugin."""
    from .services import IssuerService

    context.injector.bind_provider(
        IssuerService, ClassProvider(IssuerService, ClassProvider.Inject(Profile))
    )
