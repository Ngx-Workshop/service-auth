import { Auth } from '../iam/decorators/auth.decorator';
import { AuthType } from '../iam/enums/auth-type.enum';
import {
  Controller,
  Get,
  Header,
  SetMetadata,
  type ExecutionContext,
} from '@nestjs/common';
import {
  HealthCheck,
  HealthCheckService,
  type HealthCheckResult,
} from '@nestjs/terminus';

const HEARTBEAT = Symbol('ngx-workshop-heartbeat');

export function isHeartbeatContext(context: ExecutionContext): boolean {
  const handler = context.getHandler?.();
  return !!handler && Reflect.getMetadata(HEARTBEAT, handler) === true;
}

@Controller('health')
export class HealthController {
  constructor(private readonly health: HealthCheckService) {}

  @Auth(AuthType.None)
  @Get()
  @Header('Cache-Control', 'no-store')
  @HealthCheck()
  @SetMetadata(HEARTBEAT, true)
  check(): Promise<HealthCheckResult> {
    // Liveness only: dependency outages must not produce restart cascades.
    return this.health.check([
      () => Promise.resolve({ heartbeat: { status: 'up' } }),
    ]);
  }
}
