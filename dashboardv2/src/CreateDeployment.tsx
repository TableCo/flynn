import * as React from 'react';
import { Checkmark as CheckmarkIcon } from 'grommet-icons';
import { Box, Button } from 'grommet';

import { Release, Deployment, CreateScaleRequest } from './generated/controller_pb';
import useClient from './useClient';
import useAppRelease from './useAppRelease';
import useAppScale from './useAppScale';
import useRelease from './useRelease';
import useCallIfMounted from './useCallIfMounted';
import { ErrorHandler } from './useErrorHandler';
import Loading from './Loading';
import ReleaseComponent from './Release';
import ProcessesDiff from './ProcessesDiff';

interface Props {
	appName: string;
	releaseName?: string;
	newRelease?: Release;
	newScale?: CreateScaleRequest;
	onCancel: () => void;
	onCreate: (deployment: Deployment) => void;
	handleError: ErrorHandler;
}

export default function CreateDeployment(props: Props) {
	const client = useClient();
	const newRelease = props.newRelease;
	const newScale = props.newScale;
	const { release: currentRelease, loading: currentReleaseLoading, error: currentReleaseError } = useAppRelease(
		props.appName
	);
	const { scale: currentScale, loading: currentScaleLoading, error: currentScaleError } = useAppScale(props.appName);
	const { release: nextRelease, loading: nextReleaseLoading, error: nextReleaseError } = useRelease(
		props.releaseName || ''
	);
	const isLoading = React.useMemo(
		() => {
			return currentReleaseLoading || nextReleaseLoading || currentScaleLoading;
		},
		[currentReleaseLoading, nextReleaseLoading, currentScaleLoading]
	);
	const [isCreating, setIsCreating] = React.useState(false);
	const [isScaleToZeroConfirmed, setIsScaleToZeroConfirmed] = React.useState(!props.newScale);
	const handleError = props.handleError;

	React.useEffect(
		() => {
			const error = currentReleaseError || nextReleaseError || currentScaleError;
			if (error) {
				handleError(error);
			}
		},
		[currentReleaseError, nextReleaseError, currentScaleError, handleError]
	);

	const callIfMounted = useCallIfMounted();

	function createRelease(newRelease: Release) {
		const { appName } = props;
		return new Promise((resolve, reject) => {
			client.createRelease(appName, newRelease, (release: Release, error: Error | null) => {
				if (release && error === null) {
					resolve(release);
				} else {
					reject(error);
				}
			});
		}) as Promise<Release>;
	}

	function createDeployment(release: Release, scale?: CreateScaleRequest) {
		let resolve: (deployment: Deployment) => void, reject: (error: Error) => void;
		const p = new Promise((rs, rj) => {
			resolve = rs;
			reject = rj;
		});
		client.createDeployment(release.getName(), scale || null, (deployment: Deployment, error: Error | null) => {
			if (error) {
				reject(error);
			}
			resolve(deployment);
		});
		return p;
	}

	function handleFormSubmit(e: React.SyntheticEvent) {
		e.preventDefault();
		const { onCreate, newScale } = props;
		setIsCreating(true);
		let p = Promise.resolve(null) as Promise<any>;
		if (newRelease) {
			p = createRelease(newRelease).then((release: Release) => {
				return createDeployment(release, newScale);
			});
		} else if (nextRelease) {
			p = createDeployment(nextRelease, newScale);
		}
		p.then((deployment) => {
			callIfMounted(() => {
				onCreate(deployment);
			});
		}).catch((error: Error) => {
			callIfMounted(() => {
				setIsCreating(false);
				handleError(error);
			});
		});
	}

	if (isLoading) return <Loading />;

	if (!(nextRelease || newRelease)) {
		return null;
	}

	return (
		<Box tag="form" fill direction="column" onSubmit={handleFormSubmit} gap="small" justify="between">
			<Box>
				<h3>Review Changes</h3>
				<ReleaseComponent release={(nextRelease || newRelease) as Release} prevRelease={currentRelease} />

				{currentScale && newScale ? (
					<ProcessesDiff
						align="center"
						direction="column"
						margin="small"
						scale={currentScale}
						nextScale={newScale}
						onConfirmScaleToZeroChange={(c) => setIsScaleToZeroConfirmed(c)}
					/>
				) : null}
			</Box>

			<Box fill="horizontal" direction="row" align="end" gap="small" justify="between">
				<Button
					type="submit"
					disabled={isCreating || !isScaleToZeroConfirmed}
					primary
					icon={<CheckmarkIcon />}
					label={isCreating ? 'Deploying...' : 'Deploy'}
				/>
				<Button
					type="button"
					label="Cancel"
					onClick={(e: React.SyntheticEvent) => {
						e.preventDefault();
						props.onCancel();
					}}
				/>
			</Box>
		</Box>
	);
}
