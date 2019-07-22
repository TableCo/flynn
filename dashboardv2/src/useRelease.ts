import * as React from 'react';
import useClient from './useClient';
import { setNameFilters, setPageSize } from './client';
import { Release } from './generated/controller_pb';

export default function useRelease(releaseName: string) {
	const client = useClient();
	const [isLoading, setIsLoading] = React.useState(true);
	const [release, setRelease] = React.useState<Release | null>(null);
	const [error, setError] = React.useState<Error | null>(null);
	React.useEffect(
		() => {
			// support being called with empty name
			// (see <CreateDeployment />)
			if (!releaseName) {
				setIsLoading(false);
				setRelease(null);
				setError(null);
				return;
			}
			const cancel = client.streamReleases(
				(releases: Release[], error: Error | null) => {
					setIsLoading(false);
					if (error) {
						setError(error);
						return;
					}
					setRelease(releases[0] || null);
					setError(null);
				},
				setNameFilters(releaseName),
				setPageSize(1)
			);
			return cancel;
		},
		[releaseName, client]
	);
	return {
		loading: isLoading,
		release,
		error
	};
}
