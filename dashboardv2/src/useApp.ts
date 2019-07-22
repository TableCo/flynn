import * as React from 'react';
import useClient from './useClient';
import { setNameFilters, setPageSize, setStreamUpdates } from './client';
import { App } from './generated/controller_pb';

export default function useApp(appName: string) {
	const client = useClient();
	const [appLoading, setAppLoading] = React.useState(true);
	const [app, setApp] = React.useState<App | null>(null);
	const [error, setError] = React.useState<Error | null>(null);
	React.useEffect(
		() => {
			const cancel = client.streamApps(
				(apps: App[], error: Error | null) => {
					setAppLoading(false);
					if (error) {
						setError(error);
						return;
					}
					setApp(apps[0] || new App());
					setError(null);
				},
				setNameFilters(appName),
				setPageSize(1),
				setStreamUpdates()
			);
			return cancel;
		},
		[appName, client]
	);
	return {
		loading: appLoading,
		app,
		error
	};
}
