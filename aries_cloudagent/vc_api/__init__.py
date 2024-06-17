from ..config.injection_context import InjectionContext
from ..config.provider import ClassProvider
from ..core.profile import Profile


async def setup(context: InjectionContext):
    """Setup vc plugin."""
    from .service import VcApiService

    context.injector.bind_provider(
        VcApiService, ClassProvider(VcApiService, ClassProvider.Inject(Profile))
    )
