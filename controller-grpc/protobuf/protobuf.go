package protobuf

import (
	context "context"

	grpc "google.golang.org/grpc"
)

type authKey struct {
	key string
}

func (k *authKey) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"auth_key": k.key,
	}, nil
}

func (k *authKey) RequireTransportSecurity() bool {
	return false
}

func WithAuthKey(key string) grpc.DialOption {
	return grpc.WithPerRPCCredentials(&authKey{key})
}

func MatchLabelFilters(labels map[string]string, labelFilters []*LabelFilter) bool {
	if len(labelFilters) == 0 {
		return true
	}
	for _, f := range labelFilters {
		if f.Match(labels) {
			return true
		}
	}
	return false
}

func (f *LabelFilter) Match(labels map[string]string) bool {
	for _, e := range f.Expressions {
		if !e.Match(labels) {
			return false
		}
	}
	return true
}

func (e *LabelFilter_Expression) Match(labels map[string]string) bool {
	switch e.Op {
	case LabelFilter_Expression_OP_IN:
		if v, ok := labels[e.Key]; ok {
			for _, ev := range e.Values {
				if v == ev {
					return true
				}
			}
		}
		return false
	case LabelFilter_Expression_OP_NOT_IN:
		if v, ok := labels[e.Key]; ok {
			for _, ev := range e.Values {
				if v == ev {
					return false
				}
			}
		}
	case LabelFilter_Expression_OP_EXISTS:
		if _, ok := labels[e.Key]; !ok {
			return false
		}
	case LabelFilter_Expression_OP_NOT_EXISTS:
		if _, ok := labels[e.Key]; ok {
			return false
		}
	}
	return true
}

type ReleaseTypeMatcher struct {
	types map[ReleaseType]struct{}
}

func NewReleaseTypeMatcher(types []ReleaseType) *ReleaseTypeMatcher {
	_types := make(map[ReleaseType]struct{}, len(types))
	for _, t := range types {
		_types[t] = struct{}{}
	}
	return &ReleaseTypeMatcher{types: _types}
}

func (m *ReleaseTypeMatcher) Match(t ReleaseType) bool {
	if len(m.types) == 0 {
		return true
	}
	if _, ok := m.types[ReleaseType_ANY]; ok {
		return true
	}
	if _, ok := m.types[t]; ok {
		return true
	}
	return false
}
