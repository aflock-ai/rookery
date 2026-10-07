import {journeyRelay,type JourneyEnv} from '../_lib/journey-relay';
export const onRequest: PagesFunction<JourneyEnv> = ({request,env}) => journeyRelay(request,env,'cilock.dev');
