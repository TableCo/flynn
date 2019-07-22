import * as React from 'react';
import useClient from './useClient';
import { setNameFilters, setPageSize, setStreamCreates, setStreamUpdates } from './client';
import { Release, ExpandedDeployment, DeploymentStatus } from './generated/controller_pb';

export default function useAppRelease(appName: string) {
	const client = useClient();
	const [isLoading, setIsLoading] = React.useState(true);
	const [release, setRelease] = React.useState<Release | null>(null);
	const [error, setError] = React.useState<Error | null>(null);
	React.useEffect(
		() => {
			const cancel = client.streamDeployments(
				(deployments: ExpandedDeployment[], error: Error | null) => {
					setIsLoading(false);
					if (error) {
						setError(error);
						return;
					}
					const deployment = deployments[0] || new ExpandedDeployment();
					if (deployment.getStatus() !== DeploymentStatus.COMPLETE) {
						return;
					}
					setRelease(deployment.getNewRelease() || new Release());
					setError(null);
				},
				setNameFilters(appName),
				setPageSize(1),
				setStreamCreates(),
				setStreamUpdates()
			);
			return cancel;
		},
		[appName, client]
	);
	return {
		loading: isLoading,
		release,
		error
	};
}
