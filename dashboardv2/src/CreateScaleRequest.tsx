import * as React from 'react';
import { Box, Button } from 'grommet';
import { Checkmark as CheckmarkIcon } from 'grommet-icons';

import useClient from './useClient';
import useAppScale from './useAppScale';
import useCallIfMounted from './useCallIfMounted';
import { ErrorHandler } from './useErrorHandler';
import Loading from './Loading';
import ProcessesDiff from './ProcessesDiff';
import protoMapDiff from './util/protoMapDiff';
import protoMapReplace from './util/protoMapReplace';
import { ScaleRequest, CreateScaleRequest } from './generated/controller_pb';

interface Props {
	appName: string;
	nextScale: CreateScaleRequest;
	onCancel: () => void;
	onCreate: (scaleRequest: ScaleRequest) => void;
	handleError: ErrorHandler;
}

export default function CreateScaleRequestComponent({ appName, nextScale, onCancel, onCreate, handleError }: Props) {
	const client = useClient();
	const callIfMounted = useCallIfMounted();
	const { scale, loading: isLoading, error: scaleError } = useAppScale(appName);
	const [hasChanges, setHasChanges] = React.useState(true);
	const [isCreating, setIsCreating] = React.useState(false);
	const [isScaleToZeroConfirmed, setIsScaleToZeroConfirmed] = React.useState(false);

	React.useEffect(
		() => {
			if (scaleError) {
				handleError(scaleError);
			}
		},
		[scaleError, handleError]
	);

	// keep track of if selected scale actually changes anything
	React.useEffect(
		() => {
			const diff = protoMapDiff((scale || new ScaleRequest()).getNewProcessesMap(), nextScale.getProcessesMap());
			setHasChanges(diff.length > 0);
		},
		[nextScale, scale]
	);

	function handleSubmit(e: React.SyntheticEvent) {
		e.preventDefault();

		setIsCreating(true);

		const req = new CreateScaleRequest();
		req.setParent(nextScale.getParent());
		protoMapReplace(req.getProcessesMap(), nextScale.getProcessesMap());
		protoMapReplace(req.getTagsMap(), nextScale.getTagsMap());
		client.createScale(req, (scaleReq: ScaleRequest, error: Error | null) => {
			callIfMounted(() => {
				if (error) {
					setIsCreating(false);
					handleError(error);
					return;
				}
				onCreate(scaleReq);
			});
		});
	}

	if (isLoading) {
		return <Loading />;
	}

	if (!scale) throw new Error('<CreateScaleRequestComponent> Error: Unexpected lack of scale!');

	return (
		<Box tag="form" fill direction="column" onSubmit={handleSubmit} gap="small" justify="between">
			<Box>
				<h3>Review Changes</h3>

				<ProcessesDiff
					margin="small"
					align="center"
					scale={scale}
					nextScale={nextScale}
					onConfirmScaleToZeroChange={(c) => setIsScaleToZeroConfirmed(c)}
				/>
			</Box>

			<Box fill="horizontal" direction="row" align="end" gap="small" justify="between">
				<Button
					type="submit"
					disabled={isCreating || !hasChanges || !isScaleToZeroConfirmed}
					primary
					icon={<CheckmarkIcon />}
					label={isCreating ? 'Creating Scale Request...' : 'Create Scale Request'}
				/>
				<Button
					type="button"
					label="Cancel"
					onClick={(e: React.SyntheticEvent) => {
						e.preventDefault();
						onCancel();
					}}
				/>
			</Box>
		</Box>
	);
}
