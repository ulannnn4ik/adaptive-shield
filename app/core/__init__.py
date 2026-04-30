import redis.asyncio as redis
from config.settings import settings

_pool = None


async def get_redis():
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=50,
        )
    return redis.Redis(connection_pool=_pool)


async def close_redis():
    global _pool
    if _pool:
        await _pool.disconnect()
        _pool = None
