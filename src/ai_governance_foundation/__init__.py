"""科技战略协作基础服务的服务端基础包。"""

from .release_gate import ReleaseGateService
from .service import DomainService

__all__ = ["DomainService", "ReleaseGateService"]
