// Route registration. First match wins — specific paths before parameterised ones.

import { registerAuthRoutes }    from './auth.js';
import { registerOrgRoutes }     from './orgs.js';
import { registerSessionRoutes } from './sessions.js';
import { registerGrantRoutes }   from './grants.js';
import { registerInviteRoutes }  from './invites.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerInviteRoutes(router, deps);   // public routes before authenticated ones
  registerOrgRoutes(router, deps);
  registerGrantRoutes(router, deps);
  registerSessionRoutes(router, deps);
}
