package taxApi

import "github.com/shopspring/decimal"

type BodyItemDto struct {
	Sstid   *string          `json:"sstid,omitempty"`
	Sstt    *string          `json:"sstt,omitempty"`
	Mu      *string          `json:"mu,omitempty"`
	Am      *float64         `json:"am,omitempty"`
	Fee     *decimal.Decimal `json:"fee,omitempty"`
	Cfee    *decimal.Decimal `json:"cfee,omitempty"`
	Cut     *string          `json:"cut,omitempty"`
	Exr     *int64           `json:"exr,omitempty"`
	Prdis   *int64           `json:"prdis,omitempty"`
	Dis     *int64           `json:"dis,omitempty"`
	Adis    *int64           `json:"adis,omitempty"`
	Vra     *decimal.Decimal `json:"vra,omitempty"`
	Vam     *int64           `json:"vam,omitempty"`
	Odt     *string          `json:"odt,omitempty"`
	Odr     *decimal.Decimal `json:"odr,omitempty"`
	Odam    *int64           `json:"odam,omitempty"`
	Olt     *string          `json:"olt,omitempty"`
	Olr     *decimal.Decimal `json:"olr,omitempty"`
	Olam    *int64           `json:"olam,omitempty"`
	Consfee *int64           `json:"consfee,omitempty"`
	Spro    *int64           `json:"spro,omitempty"`
	Bros    *int64           `json:"bros,omitempty"`
	Tcpbs   *int64           `json:"tcpbs,omitempty"`
	Cop     *int64           `json:"cop,omitempty"`
	Bsrn    *string          `json:"bsrn,omitempty"`
	Vop     *int64           `json:"vop,omitempty"`
	Tsstam  *int64           `json:"tsstam,omitempty"`
	Nw      *decimal.Decimal `json:"nw,omitempty"`
	Ssrv    *int64           `json:"ssrv,omitempty"`
	Sscv    *int64           `json:"sscv,omitempty"`
	Cui     *decimal.Decimal `json:"cui,omitempty"`
	Cpr     *decimal.Decimal `json:"cpr,omitempty"`
	Sovat   *int64           `json:"sovat,omitempty"`
}

type HeaderDto struct {
	Indati2m *int64            `json:"indati2m,omitempty"`
	Indatim  *int64            `json:"indatim,omitempty"`
	Inty     *int32            `json:"inty,omitempty"`
	Ft       *int32            `json:"ft,omitempty"`
	Inno     *string           `json:"inno,omitempty"`
	Irtaxid  *string           `json:"irtaxid,omitempty"`
	Scln     *string           `json:"scln,omitempty"`
	Setm     *int32            `json:"setm,omitempty"`
	Tins     *string           `json:"tins,omitempty"`
	Cap      *int64            `json:"cap,omitempty"`
	Bid      *string           `json:"bid,omitempty"`
	Insp     *int64            `json:"insp,omitempty"`
	Tvop     *int64            `json:"tvop,omitempty"`
	Bpc      *string           `json:"bpc,omitempty"`
	Tax17    *int64            `json:"tax17,omitempty"`
	Taxid    *string           `json:"taxid,omitempty"`
	Inp      *int32            `json:"inp,omitempty"`
	Scc      *string           `json:"scc,omitempty"`
	Ins      *int32            `json:"ins,omitempty"`
	Billid   *string           `json:"billid,omitempty"`
	Tprdis   *int64            `json:"tprdis,omitempty"`
	Tdis     *int64            `json:"tdis,omitempty"`
	Tadis    *int64            `json:"tadis,omitempty"`
	Tvam     *int64            `json:"tvam,omitempty"`
	Todam    *int64            `json:"todam,omitempty"`
	Tbill    *int64            `json:"tbill,omitempty"`
	Tob      *int32            `json:"tob,omitempty"`
	Tinb     *string           `json:"tinb,omitempty"`
	Sbc      *string           `json:"sbc,omitempty"`
	Bbc      *string           `json:"bbc,omitempty"`
	Bpn      *string           `json:"bpn,omitempty"`
	Crn      *string           `json:"crn,omitempty"`
	Cdcn     *string           `json:"cdcn,omitempty"`
	Cdcd     *int32            `json:"cdcd,omitempty"`
	Tonw     *decimal.Decimal  `json:"tonw,omitempty"`
	Torv     *int64            `json:"torv,omitempty"`
	Tocv     *decimal.Decimal  `json:"tocv,omitempty"`
	Tinc     *string           `json:"tinc,omitempty"`
	Lno      *string           `json:"lno,omitempty"`
	Lrno     *string           `json:"lrno,omitempty"`
	Ocu      *string           `json:"ocu,omitempty"`
	Oci      *string           `json:"oci,omitempty"`
	Dco      *string           `json:"dco,omitempty"`
	Dci      *string           `json:"dci,omitempty"`
	Tid      *string           `json:"tid,omitempty"`
	Rid      *string           `json:"rid,omitempty"`
	Lt       *int8             `json:"lt,omitempty"`
	Cno      *string           `json:"cno,omitempty"`
	Did      *string           `json:"did,omitempty"`
	Sg       []ShippingGoodDto `json:"sg,omitempty"`
	Asn      *string           `json:"asn,omitempty"`
	Asd      *int32            `json:"asd,omitempty"`
}

type ShippingGoodDto struct {
	Sgid *string `json:"sgid,omitempty"`
	Sgt  *string `json:"sgt,omitempty"`
}

type PaymentItemDto struct {
	Iinn *string `json:"iinn,omitempty"`
	Acn  *string `json:"acn,omitempty"`
	Trmn *string `json:"trmn,omitempty"`
	Trn  *string `json:"trn,omitempty"`
	Pcn  *string `json:"pcn,omitempty"`
	Pid  *string `json:"pid,omitempty"`
	Pdt  *int64  `json:"pdt,omitempty"`
	Pmt  *int32  `json:"pmt,omitempty"`
	Pv   *int64  `json:"pv,omitempty"`
}

type ExtensionItemDto struct {
	// Empty struct (equivalent to the Java class with no fields)
}

type InvoiceDto struct {
	Header    *HeaderDto         `json:"header,omitempty"`
	Body      []BodyItemDto      `json:"body,omitempty"`
	Payments  []PaymentItemDto   `json:"payments,omitempty"`
	Extension []ExtensionItemDto `json:"extension,omitempty"`
}
