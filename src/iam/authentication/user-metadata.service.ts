import { Injectable, Logger } from '@nestjs/common';
import axios from 'axios';
import { localAdminMode } from '../../local-admin-development';
import { logOperation } from '../../observability/observability';

@Injectable()
export class UserMetadataService {
  private readonly logger = new Logger(UserMetadataService.name);
  private readonly client = axios.create({
    baseURL: localAdminMode()
      ? 'http://127.0.0.1:3004'
      : process.env.USER_METADATA_URL,
    timeout: 3000,
  });

  async upsert(uuid: unknown, accessToken: string): Promise<void> {
    try {
      await logOperation(
        this.logger,
        'user_metadata_upsert',
        async () => {
          await this.client.put(
            '/user-metadata',
            { uuid },
            { headers: { Authorization: `Bearer ${accessToken}` } },
          );
        },
        'warn',
      );
    } catch {
      // Metadata remains best-effort; logOperation already records a safe failure.
    }
  }
}
