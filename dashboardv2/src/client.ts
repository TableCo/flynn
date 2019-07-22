import { grpc } from '@improbable-eng/grpc-web';
import { Timestamp } from 'google-protobuf/google/protobuf/timestamp_pb';
import { BrowserHeaders } from 'browser-headers';

import Config, { PrivateConfig } from './config';
import { ControllerClient, ServiceError, Status, ResponseStream } from './generated/controller_pb_service';
import {
	StreamAppsRequest,
	StreamAppsResponse,
	UpdateAppRequest,
	App,
	StreamReleasesRequest,
	StreamReleasesResponse,
	CreateReleaseRequest,
	Release,
	ReleaseTypeMap,
	ScaleRequest,
	StreamScalesRequest,
	StreamScalesResponse,
	ScaleRequestStateMap,
	CreateScaleRequest,
	CreateDeploymentRequest,
	Deployment,
	ExpandedDeployment,
	StreamDeploymentsRequest,
	StreamDeploymentsResponse,
	DeploymentEvent,
	LabelFilter
} from './generated/controller_pb';

export interface Client {
	// auth
	login: (token: string, cb: AuthCallback) => CancelFunc;
	logout: (cb: AuthCallback) => CancelFunc;

	// read API
	streamApps: (cb: AppsCallback, ...reqModifiers: RequestModifier<StreamAppsRequest>[]) => CancelFunc;
	streamReleases: (cb: ReleasesCallback, ...reqModifiers: RequestModifier<StreamReleasesRequest>[]) => CancelFunc;
	streamScales: (cb: ScaleRequestsCallback, ...reqModifiers: RequestModifier<StreamScalesRequest>[]) => CancelFunc;
	streamDeployments: (
		cb: DeploymentsCallback,
		...reqModifiers: RequestModifier<StreamDeploymentsRequest>[]
	) => CancelFunc;

	// write API
	updateApp: (app: App, cb: AppCallback) => CancelFunc;
	createScale: (req: CreateScaleRequest, cb: CreateScaleCallback) => CancelFunc;
	createRelease: (parentName: string, release: Release, cb: ReleaseCallback) => CancelFunc;
	createDeployment: (parentName: string, scale: CreateScaleRequest | null, cb: DeploymentCallback) => CancelFunc;
}

interface AuthStatus {
	authenticated: boolean;
}

export type ErrorWithCode = Error & ServiceError;
export type CancelFunc = () => void;
export type AuthCallback = (s: AuthStatus | null, error: Error | null) => void;
export type AppsCallback = (apps: App[], error: ErrorWithCode | null) => void;
export type AppCallback = (app: App, error: ErrorWithCode | null) => void;
export type ReleasesCallback = (releases: Release[], error: ErrorWithCode | null) => void;
export type CreateScaleCallback = (sr: ScaleRequest, error: ErrorWithCode | null) => void;
export type ReleaseCallback = (release: Release, error: ErrorWithCode | null) => void;
export type DeploymentCallback = (deployment: Deployment, error: ErrorWithCode | null) => void;
export type ScaleRequestsCallback = (scaleRequests: ScaleRequest[], error: ErrorWithCode | null) => void;
export type DeploymentsCallback = (deployments: ExpandedDeployment[], error: ErrorWithCode | null) => void;

export type RequestModifier<T> = {
	(req: T): void;
	key: string;
};

export interface PaginatableRequest {
	getPageSize(): number;
	setPageSize(value: number): void;

	getPageToken(): string;
	setPageToken(value: string): void;
}

export function setPageSize(pageSize: number): RequestModifier<PaginatableRequest> {
	return Object.assign(
		(req: PaginatableRequest) => {
			req.setPageSize(pageSize);
		},
		{ key: `pageSize--${pageSize}` }
	);
}

export interface NameFilterable {
	clearNameFiltersList(): void;
	getNameFiltersList(): Array<string>;
	setNameFiltersList(value: Array<string>): void;
	addNameFilters(value: string, index?: number): string;
}

export function setNameFilters(...filterNames: string[]): RequestModifier<NameFilterable> {
	return Object.assign(
		(req: NameFilterable) => {
			req.setNameFiltersList(filterNames);
		},
		{ key: `nameFilters--${filterNames.join('|')}` }
	);
}

export interface CreateStreamable {
	setStreamCreates(value: boolean): void;
}

export function setStreamCreates(): RequestModifier<CreateStreamable> {
	return Object.assign(
		(req: CreateStreamable) => {
			req.setStreamCreates(true);
		},
		{ key: 'streamCreates' }
	);
}

export interface UpdateStreamable {
	setStreamUpdates(value: boolean): void;
}

export function setStreamUpdates(): RequestModifier<UpdateStreamable> {
	return Object.assign(
		(req: UpdateStreamable) => {
			req.setStreamUpdates(true);
		},
		{ key: 'streamUpdates' }
	);
}

export function listDeploymentsRequestFilterType(
	...filterTypes: Array<ReleaseTypeMap[keyof ReleaseTypeMap]>
): RequestModifier<StreamDeploymentsRequest> {
	return Object.assign(
		(req: StreamDeploymentsRequest) => {
			req.setTypeFiltersList(filterTypes);
		},
		{ key: `filterTypes--${filterTypes.join('|')}` }
	);
}

export function excludeAppsWithLabels(labels: [string, string][]): RequestModifier<StreamAppsRequest> {
	return Object.assign(
		(req: StreamAppsRequest) => {
			labels.forEach(([key, val]: [string, string]) => {
				const f = new LabelFilter();
				const e = new LabelFilter.Expression();
				e.setKey(key);
				e.addValues(val);
				e.setOp(LabelFilter.Expression.Operator.OP_NOT_IN);
				f.addExpressions(e);
				req.addLabelFilters(f);
			});
		},
		{ key: `excludeAppsWithLabels--${JSON.stringify(labels)}` }
	);
}

export function filterScalesByState(
	...stateFilters: Array<ScaleRequestStateMap[keyof ScaleRequestStateMap]>
): RequestModifier<StreamScalesRequest> {
	return Object.assign(
		(req: StreamScalesRequest) => {
			req.setStateFiltersList(stateFilters);
		},
		{ key: `stateFilters--${JSON.stringify(stateFilters)}` }
	);
}

const UnknownError: ErrorWithCode = Object.assign(new Error('Unknown error'), {
	code: grpc.Code.Unknown,
	metadata: new grpc.Metadata()
});

export function isNotFoundError(error: Error): boolean {
	return (error as ErrorWithCode).code === grpc.Code.NotFound;
}

interface Cancellable {
	cancel(): void;
}

function buildCancelFunc(req: Cancellable): CancelFunc {
	let cancelled = false;
	return () => {
		if (cancelled) return;
		cancelled = true;
		req.cancel();
	};
}

function convertServiceError(error: ServiceError): ErrorWithCode {
	return Object.assign(new Error(error.message), error);
}

function buildStatusError(s: Status): ErrorWithCode {
	return Object.assign(new Error(s.details), s);
}

function buildStreamErrorHandler<T>(stream: ResponseStream<T>, cb: (error: ErrorWithCode) => void) {
	stream.on('status', (s: Status) => {
		if (s.code !== grpc.Code.OK) {
			cb(buildStatusError(s));
		}
	});
}

function compareTimestamps(a: Timestamp | undefined, b: Timestamp | undefined): 1 | 0 | -1 {
	const ad = (a || new Timestamp()).toDate();
	const bd = (b || new Timestamp()).toDate();
	if (ad === bd) {
		return 0;
	}
	if (ad > bd) {
		return 1;
	}
	return -1;
}

const __memoizedStreams = {} as { [key: string]: ResponseStream<any> };
const __memoizedStreamN = {} as { [key: string]: number };
const __memoizedStreamResponses = {} as { [key: string]: any };
function memoizedStream<T>(
	contextKey: string,
	streamKey: string,
	opts: { init: () => ResponseStream<T>; mergeResponses: (prev: T | null, res: T) => T }
): [ResponseStream<T>, T | undefined] {
	const key = contextKey + streamKey;
	function cleanup(streamEnded = false) {
		const n = (__memoizedStreamN[key] = (__memoizedStreamN[key] || 0) - 1);
		if (n === 0 || streamEnded) {
			delete __memoizedStreams[key];
			delete __memoizedStreamN[key];
			delete __memoizedStreamResponses[key];
		}
		return n;
	}

	__memoizedStreamN[key] = (__memoizedStreamN[key] || 0) + 1;

	let stream = __memoizedStreams[key];
	if (stream) {
		return [stream as ResponseStream<T>, __memoizedStreamResponses[key] as T | undefined];
	}
	let dataCallbacks = [] as Array<(data: T) => void>;
	stream = opts.init();
	stream.on('data', (data: T) => {
		data = opts.mergeResponses(__memoizedStreamResponses[key] || null, data);
		__memoizedStreamResponses[key] = data;
		dataCallbacks.forEach((cb) => cb(data));
	});
	let cancel = stream.cancel;
	stream.on('end', () => {
		cleanup(true);
		cancel = () => {};
	});
	stream.cancel = () => {
		if (cleanup() === 0) {
			cancel();
		}
	};
	const s = {
		on: (typ: string, handler: Function): ResponseStream<T> => {
			switch (typ) {
				case 'data':
					dataCallbacks.push(handler as ((message: T) => void));
					break;
				case 'end':
					stream.on('end', handler as (() => void));
					break;
				case 'status':
					stream.on('status', handler as ((status: Status) => void));
					break;
				default:
			}
			return s;
		},
		cancel: stream.cancel
	};
	__memoizedStreams[key] = stream;
	return [s, undefined];
}

class _Client implements Client {
	private _cc: ControllerClient;
	constructor(cc: ControllerClient) {
		this._cc = cc;
	}

	public login(token: string, cb: AuthCallback): CancelFunc {
		var controller = new AbortController();
		var signal = controller.signal;
		fetch('/login', {
			method: 'POST',
			signal,
			mode: 'cors',
			cache: 'no-cache',
			credentials: 'same-origin',
			headers: {
				'Content-Type': 'application/json'
			},
			body: JSON.stringify({ token })
		})
			.then((response) => response.json())
			.then((conf: PrivateConfig) => {
				Object.assign(Config, conf);
				cb({ authenticated: true }, null);
			})
			.catch((error) => {
				cb(null, error);
			});
		return () => {
			controller.abort();
		};
	}

	public logout(cb: AuthCallback): CancelFunc {
		var controller = new AbortController();
		var signal = controller.signal;
		fetch('/logout', {
			method: 'POST',
			signal,
			mode: 'cors',
			cache: 'no-cache',
			credentials: 'same-origin'
		})
			.then(() => {
				Config.unsetPrivateConfig();
				cb({ authenticated: false }, null);
			})
			.catch((error) => {
				cb(null, error);
			});
		return () => {
			controller.abort();
		};
	}

	public streamApps(cb: AppsCallback, ...reqModifiers: RequestModifier<StreamAppsRequest>[]): CancelFunc {
		const streamKey = reqModifiers.map((m) => m.key).join(':');
		const [stream, lastResponse] = memoizedStream('streamApps', streamKey, {
			init: () => {
				const req = new StreamReleasesRequest();
				reqModifiers.forEach((m) => m(req));
				return this._cc.streamApps(req, this.metadata());
			},
			mergeResponses: (prev: StreamAppsResponse | null, res: StreamAppsResponse): StreamAppsResponse => {
				const appIndices = new Map<string, number>();
				const apps = [] as App[];
				(prev ? prev.getAppsList() : []).forEach((app, index) => {
					appIndices.set(app.getName(), index);
					apps.push(app);
				});
				res.getAppsList().forEach((app) => {
					const index = appIndices.get(app.getName());
					if (index !== undefined) {
						apps[index] = app;
					} else {
						apps.push(app);
					}
				});
				apps.sort((a, b) => {
					return a.getDisplayName().localeCompare(b.getDisplayName());
				});
				res.setAppsList(apps);
				return res;
			}
		});
		stream.on('data', (response: StreamAppsResponse) => {
			cb(response.getAppsList(), null);
		});
		if (lastResponse) {
			cb(lastResponse.getAppsList(), null);
		}
		buildStreamErrorHandler(stream, (error: ErrorWithCode) => {
			cb([], error);
		});
		return buildCancelFunc(stream);
	}

	public streamReleases(cb: ReleasesCallback, ...reqModifiers: RequestModifier<StreamReleasesRequest>[]): CancelFunc {
		const streamKey = reqModifiers.map((m) => m.key).join(':');
		const [stream, lastResponse] = memoizedStream('streamReleases', streamKey, {
			init: () => {
				const req = new StreamReleasesRequest();
				reqModifiers.forEach((m) => m(req));
				return this._cc.streamReleases(req, this.metadata());
			},
			mergeResponses: (prev: StreamReleasesResponse | null, res: StreamReleasesResponse): StreamReleasesResponse => {
				const releaseIndices = new Map<string, number>();
				const releases = [] as Release[];
				(prev ? prev.getReleasesList() : []).forEach((release, index) => {
					releaseIndices.set(release.getName(), index);
					releases.push(release);
				});
				res.getReleasesList().forEach((release) => {
					const index = releaseIndices.get(release.getName());
					if (index !== undefined) {
						releases[index] = release;
					} else {
						releases.push(release);
					}
				});
				releases.sort((a, b) => {
					return compareTimestamps(b.getCreateTime(), a.getCreateTime());
				});
				res.setReleasesList(releases);
				return res;
			}
		});
		stream.on('data', (response: StreamReleasesResponse) => {
			cb(response.getReleasesList(), null);
		});
		if (lastResponse) {
			cb(lastResponse.getReleasesList(), null);
		}
		buildStreamErrorHandler(stream, (error: ErrorWithCode) => {
			cb([], error);
		});
		return buildCancelFunc(stream);
	}

	public streamScales(cb: ScaleRequestsCallback, ...reqModifiers: RequestModifier<StreamScalesRequest>[]): CancelFunc {
		const streamKey = reqModifiers.map((m) => m.key).join(':');
		const [stream, lastResponse] = memoizedStream('streamScales', streamKey, {
			init: () => {
				const req = new StreamScalesRequest();
				reqModifiers.forEach((m) => m(req));
				return this._cc.streamScales(req, this.metadata());
			},
			mergeResponses: (prev: StreamScalesResponse | null, res: StreamScalesResponse): StreamScalesResponse => {
				const scaleIndices = new Map<string, number>();
				const scales = [] as ScaleRequest[];
				(prev ? prev.getScaleRequestsList() : []).forEach((scale, index) => {
					scaleIndices.set(scale.getName(), index);
					scales.push(scale);
				});
				res.getScaleRequestsList().forEach((scale) => {
					const index = scaleIndices.get(scale.getName());
					if (index !== undefined) {
						scales[index] = scale;
					} else {
						scales.push(scale);
					}
				});
				scales.sort((a, b) => {
					return compareTimestamps(b.getCreateTime(), a.getCreateTime());
				});
				res.setScaleRequestsList(scales);
				return res;
			}
		});
		stream.on('data', (response: StreamScalesResponse) => {
			cb(response.getScaleRequestsList(), null);
		});
		if (lastResponse) {
			cb(lastResponse.getScaleRequestsList(), null);
		}
		buildStreamErrorHandler(stream, (error: ErrorWithCode) => {
			cb([], error);
		});
		return buildCancelFunc(stream);
	}

	public streamDeployments(
		cb: DeploymentsCallback,
		...reqModifiers: RequestModifier<StreamDeploymentsRequest>[]
	): CancelFunc {
		const streamKey = reqModifiers.map((m) => m.key).join(':');
		const [stream, lastResponse] = memoizedStream('streamDeployments', streamKey, {
			init: () => {
				const req = new StreamDeploymentsRequest();
				reqModifiers.forEach((m) => m(req));
				return this._cc.streamDeployments(req, this.metadata());
			},
			mergeResponses: (
				prev: StreamDeploymentsResponse | null,
				res: StreamDeploymentsResponse
			): StreamDeploymentsResponse => {
				const deploymentIndices = new Map<string, number>();
				const deployments = [] as ExpandedDeployment[];
				(prev ? prev.getDeploymentsList() : []).forEach((deployment, index) => {
					deploymentIndices.set(deployment.getName(), index);
					deployments.push(deployment);
				});
				res.getDeploymentsList().forEach((deployment) => {
					const index = deploymentIndices.get(deployment.getName());
					if (index !== undefined) {
						deployments[index] = deployment;
					} else {
						deployments.push(deployment);
					}
				});
				res.setDeploymentsList(
					deployments.sort((a, b) => {
						return compareTimestamps(b.getCreateTime(), a.getCreateTime());
					})
				);
				return res;
			}
		});
		stream.on('data', (response: StreamDeploymentsResponse) => {
			cb(response.getDeploymentsList(), null);
		});
		if (lastResponse) {
			cb(lastResponse.getDeploymentsList(), null);
		}
		buildStreamErrorHandler(stream, (error: ErrorWithCode) => {
			cb([], error);
		});
		return buildCancelFunc(stream);
	}

	public updateApp(app: App, cb: AppCallback): CancelFunc {
		// TODO(jvatic): implement update_mask to include only changed fields
		const req = new UpdateAppRequest();
		req.setApp(app);
		return buildCancelFunc(
			this._cc.updateApp(req, this.metadata(), (error: ServiceError | null, response: App | null) => {
				if (response && error === null) {
					cb(response, null);
				} else if (error) {
					cb(new App(), convertServiceError(error));
				} else {
					cb(new App(), UnknownError);
				}
			})
		);
	}

	public createScale(req: CreateScaleRequest, cb: CreateScaleCallback): CancelFunc {
		return buildCancelFunc(
			this._cc.createScale(req, this.metadata(), (error: ServiceError | null, response: ScaleRequest | null) => {
				if (response && error === null) {
					cb(response, null);
				} else if (error) {
					cb(new ScaleRequest(), convertServiceError(error));
				} else {
					cb(new ScaleRequest(), UnknownError);
				}
			})
		);
	}

	public createRelease(parentName: string, release: Release, cb: ReleaseCallback): CancelFunc {
		const req = new CreateReleaseRequest();
		req.setParent(parentName);
		req.setRelease(release);
		return buildCancelFunc(
			this._cc.createRelease(req, this.metadata(), (error: ServiceError | null, response: Release | null) => {
				if (response && error === null) {
					cb(response, null);
				} else if (error) {
					cb(new Release(), convertServiceError(error));
				} else {
					cb(new Release(), UnknownError);
				}
			})
		);
	}

	public createDeployment(parentName: string, scale: CreateScaleRequest | null, cb: DeploymentCallback): CancelFunc {
		const req = new CreateDeploymentRequest();
		req.setParent(parentName);
		if (scale) {
			req.setScaleRequest(scale);
		}

		let deployment = null as Deployment | null;
		const stream = this._cc.createDeployment(req, this.metadata());
		stream.on('data', (event: DeploymentEvent) => {
			const d = event.getDeployment();
			if (d) {
				deployment = d;
			}
		});
		stream.on('status', (s: Status) => {
			if (s.code === grpc.Code.OK && deployment) {
				cb(deployment, null);
			} else {
				cb(new Deployment(), buildStatusError(s));
			}
		});
		stream.on('end', () => {});
		return buildCancelFunc(stream);
	}

	private metadata(): grpc.Metadata {
		const headers = new BrowserHeaders({});
		if (Config.CONTROLLER_AUTH_KEY) {
			headers.set('auth_key', Config.CONTROLLER_AUTH_KEY);
		}
		return headers;
	}
}

const cc = new ControllerClient(Config.CONTROLLER_HOST, {});

export default new _Client(cc);
