package coinmanager

import (
	"encoding/hex"
	"testing"

	"github.com/spf13/viper"
)

func TestExtractPkScriptAddr(t *testing.T) {
	type args struct {
		PkScript string
		coinType string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		netParam string
	}{
		// TODO: Add test cases.
		{
			name: "btc_main_net_pubkeyhash_test",
			args: args{
				PkScript: "76a914d3056c99ffdbb7d53be1ae4fdbd26e5aa609c78788ac",
				coinType: "btc",
			},
			want:     "1LEn5MmCqyrezQTc3yfCqg99jAC7STXLBa",
			netParam: "mainnet",
		},
		{
			name: "btc_main_net_scripthash_test",
			args: args{
				PkScript: "a914082f357ee6ff4a4b5e9b9f75574b6c2ac448d10187",
				coinType: "btc",
			},
			want:     "32SHtDRRNE1VoBMgsNnVLBsjH8o55yDwMR",
			netParam: "mainnet",
		},
		{
			name: "btc_regtest_pubkey_test",
			args: args{
				PkScript: "210245f2ed2c4da0fcab3275914bb3472d91bca5c64c29abd16f447b40a1fdfc5154ac",
				coinType: "btc",
			},
			want:     "mwai3fxerW34oPNwm6zxqFVZcNyWAWyGj8",
			netParam: "regtest",
		},
		{
			name: "btc_regtest_nulldata_test",
			args: args{
				PkScript: "6a24aa21a9ede2f61c3f71d1defd3fa999dfa36953755c690689799962b48bebd836974e8cf9",
				coinType: "btc",
			},
			want:     "",
			netParam: "regtest",
		},
		{
			name: "bch_mainnet_pubkeyhash_test",
			args: args{
				PkScript: "76a914d93d321605845dad585643e394521267336c80ca88ac",
				coinType: "bch",
			},
			want:     "bitcoincash:qrvn6vskqkz9mt2c2ep789zjzfnnxmyqegjtyg7m55",
			netParam: "mainnet",
		},
		{
			name: "bch_regtest_pubkeyhash_test",
			args: args{
				PkScript: "a9147134f27734b931c98029f4889b7931315f941b4f87",
				coinType: "bch",
			},
			want:     "bchreg:ppcnfunhxjunrjvq986g3xmexyc4l9qmfua8n9ylsh",
			netParam: "regtest",
		},
	}
	for _, tt := range tests {
		viper.Set("net_param", tt.netParam)
		t.Run(tt.name, func(t *testing.T) {
			PkScript, _ := hex.DecodeString(tt.args.PkScript)
			if got := ExtractPkScriptAddr(PkScript, tt.args.coinType); got != tt.want {
				t.Errorf("ExtractPkScriptAddr() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractPkScriptMessage(t *testing.T) {
	type args struct {
		PkScript string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{PkScript: ""},
			want: "",
		},
		{
			name: "test2",
			args: args{PkScript: "a9147134f27734b931c98029f4889b7931315f941b4f87"},
			want: "",
		},
		{
			name: "test3",
			args: args{PkScript: "6a427b2261223a22307862443432373933453835443339393130443739363039434142343936313338413235453632363864222c2262223a22657468222c226e223a317d"},
			want: `{"a":"0xbD42793E85D39910D79609CAB496138A25E6268d","b":"eth","n":1}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			PkScript, _ := hex.DecodeString(tt.args.PkScript)
			if got := ExtractPkScriptMessage(PkScript); got != tt.want {
				t.Errorf("ExtractPkScriptMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetMultiSigAddress(t *testing.T) {
	type args struct {
		addressPubkeyList []string
		nrequired         int
		coinType          string
		netParam          string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "test1",
			args: args{
				addressPubkeyList: []string{"02db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff88", "02374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851", "0351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e6711283"},
				nrequired:         2,
				coinType:          "btc",
				netParam:          "mainnet",
			},
			want:    "3C1bi3xS8XxMJJrC3HqujjHz2wzM7hWXjc",
			want1:   "522102db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff882102374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851210351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e671128353ae",
			wantErr: false,
		},
		{
			name: "test2",
			args: args{
				addressPubkeyList: []string{"02db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff88", "02374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851", "0351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e6711283"},
				nrequired:         3,
				coinType:          "btc",
				netParam:          "mainnet",
			},
			want:    "3AswyHW5AJoh8x2fAwztgZK2UyEqUPUJNw",
			want1:   "532102db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff882102374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851210351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e671128353ae",
			wantErr: false,
		},
		{
			name: "test3",
			args: args{
				addressPubkeyList: []string{"02db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff88", "02374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851", "0351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e6711283"},
				nrequired:         2,
				coinType:          "bch",
				netParam:          "mainnet",
			},
			want:    "bitcoincash:ppcnfunhxjunrjvq986g3xmexyc4l9qmfurfpr9m5d",
			want1:   "522102db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff882102374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851210351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e671128353ae",
			wantErr: false,
		},
		{
			name: "test4",
			args: args{
				addressPubkeyList: []string{"02db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff88", "02374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851", "0351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e6711283"},
				nrequired:         3,
				coinType:          "bch",
				netParam:          "regtest",
			},
			want:    "bchreg:ppjv56rkje4fgyhk8h8gad7dacurdhucp57mtwvjtn",
			want1:   "532102db61dbdac4292174b7300f0359dd0ecfc1c7cf215d6e1f4720a83a1f6dc1ff882102374a328b3059dbb491cb86943537b5addb4e5a122be909aada43affd85c9c851210351525878131c782b1851d42fef61fa838fb7343636e525cadfddebf6e671128353ae",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		viper.Set("net_param", tt.args.netParam)
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := GetMultiSigAddress(tt.args.addressPubkeyList, tt.args.nrequired, tt.args.coinType)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetMultiSigAddress() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetMultiSigAddress() got = %v, want %v", got, tt.want)
			}
			want1 := hex.EncodeToString(got1)
			if want1 != tt.want1 {
				t.Errorf("GetMultiSigAddress() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
