package controller

import "testing"

func TestEvalThreshold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		expr    string
		value   float64
		want    bool
		wantErr bool
	}{
		{
			name:    "greater than true",
			expr:    "> 80",
			value:   90,
			want:    true,
			wantErr: false,
		},
		{
			name:    "greater than false",
			expr:    "> 80",
			value:   70,
			want:    false,
			wantErr: false,
		},
		{
			name:    "greater than or equal true when equal",
			expr:    ">= 80",
			value:   80,
			want:    true,
			wantErr: false,
		},
		{
			name:    "greater than or equal false",
			expr:    ">= 80",
			value:   79.9,
			want:    false,
			wantErr: false,
		},
		{
			name:    "less than true",
			expr:    "< 80",
			value:   70,
			want:    true,
			wantErr: false,
		},
		{
			name:    "less than false",
			expr:    "< 80",
			value:   80,
			want:    false,
			wantErr: false,
		},
		{
			name:    "less than or equal true when equal",
			expr:    "<= 80",
			value:   80,
			want:    true,
			wantErr: false,
		},
		{
			name:    "equal true",
			expr:    "== 80",
			value:   80,
			want:    true,
			wantErr: false,
		},
		{
			name:    "equal false",
			expr:    "== 80",
			value:   81,
			want:    false,
			wantErr: false,
		},
		{
			name:    "not equal true",
			expr:    "!= 80",
			value:   81,
			want:    true,
			wantErr: false,
		},
		{
			name:    "not equal false",
			expr:    "!= 80",
			value:   80,
			want:    false,
			wantErr: false,
		},
		{
			name:    "trim leading spaces",
			expr:    "   >= 10",
			value:   10,
			want:    true,
			wantErr: false,
		},
		{
			name:    "decimal threshold",
			expr:    "> 80.5",
			value:   80.6,
			want:    true,
			wantErr: false,
		},
		{
			name:    "negative threshold",
			expr:    "< -1",
			value:   -2,
			want:    true,
			wantErr: false,
		},
		{
			name:    "invalid operator",
			expr:    "= 80",
			value:   80,
			want:    false,
			wantErr: true,
		},
		{
			name:    "missing number",
			expr:    ">=",
			value:   80,
			want:    false,
			wantErr: true,
		},
		{
			name:    "invalid number",
			expr:    "> abc",
			value:   80,
			want:    false,
			wantErr: true,
		},
		{
			name:    "empty expression",
			expr:    "",
			value:   80,
			want:    false,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := evalThreshold(tt.expr, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("evalThreshold(%q, %v) error = %v, wantErr %v", tt.expr, tt.value, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("evalThreshold(%q, %v) = %v, want %v", tt.expr, tt.value, got, tt.want)
			}
		})
	}
}
