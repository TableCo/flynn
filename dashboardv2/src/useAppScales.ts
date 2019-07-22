import * as React from 'react';
import useClient from './useClient';
import { setNameFilters, setStreamCreates, setStreamUpdates } from './client';
import { ScaleRequest } from './generated/controller_pb';

export default function useAppScales(appName: string, enabled: boolean = false) {
	const client = useClient();
	const [loading, setLoading] = React.useState(enabled);
	const [scales, setScales] = React.useState<ScaleRequest[]>([]);
	const [error, setError] = React.useState<Error | null>(null);
	React.useEffect(
		() => {
			if (!enabled) {
				return;
			}

			const cancel = client.streamScales(
				(scales: ScaleRequest[], error: Error | null) => {
					if (error) {
						setError(error);
						return;
					}
					setScales(scales);
					setLoading(false);
					setError(null);
				},
				setNameFilters(appName),
				setStreamCreates(),
				setStreamUpdates()
			);
			return cancel;
		},
		[appName, enabled, client]
	);
	return {
		loading,
		scales,
		error
	};
}
