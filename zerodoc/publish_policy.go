package zerodoc

import (
	"fmt"
	"strings"
)

type FilterCode uint64

const (
	FilterTapType FilterCode = 0x1 << iota
	FilterAclGid
	FilterL3EpcID
	FilterL3DeviceType
	FilterL3DeviceID
	FilterL3EpcID0
	FilterL3EpcID1
	FilterACLDirection
	FilterDirection
	FilterSide
)

type PublishPolicy struct {
	Database    string
	Measurement string
	TagCode     uint64
	IsMatched   bool // 若该policy被匹配到，则置为true

	Code FilterCode
	// 需要和tag.go以及trident.proto的PublishAcl 中定义的一致
	TAPType      TAPTypeEnum
	ACLGID       uint16
	L3EpcID      int16
	L3DeviceID   uint16
	L3DeviceType DeviceType
	L3EpcID0     int16
	L3EpcID1     int16
	ACLDirection ACLDirectionEnum
	Direction    DirectionEnum
	Side         uint8
}

// 用于debug 打印
func (p *PublishPolicy) FilterString() string {
	out := []string{}
	code := p.Code

	if code&FilterTapType != 0 {
		out = append(out, fmt.Sprintf("tap_type=%d", p.TAPType))
	}
	if code&FilterAclGid != 0 {
		out = append(out, fmt.Sprintf("acl_gid=%d", p.ACLGID))
	}
	if code&FilterL3EpcID != 0 {
		out = append(out, fmt.Sprintf("l3_epc_id=%d", p.L3EpcID))
	}
	if code&FilterL3DeviceID != 0 {
		out = append(out, fmt.Sprintf("l3_device_id=%d", p.L3DeviceID))
	}
	if code&FilterL3DeviceType != 0 {
		out = append(out, fmt.Sprintf("l3_device_type=%d", p.L3DeviceType))
	}
	if code&FilterL3EpcID0 != 0 {
		out = append(out, fmt.Sprintf("l3_epc_id_0=%d", p.L3EpcID0))
	}
	if code&FilterL3EpcID1 != 0 {
		out = append(out, fmt.Sprintf("l3_epc_id_1=%d", p.L3EpcID1))
	}
	if code&FilterACLDirection != 0 {
		out = append(out, fmt.Sprintf("acl_direction=%d", p.ACLDirection))
	}
	if code&FilterDirection != 0 {
		out = append(out, fmt.Sprintf("direction=%d", p.Direction))
	}
	if code&FilterSide != 0 {
		out = append(out, fmt.Sprintf("side=%d", p.Side))
	}

	return strings.Join(out, ",")
}

// 用于debug 打印
func (p *PublishPolicy) String() string {
	return fmt.Sprintf("\n db: %s measurement: %s tag_code: %016x filters: %s\n",
		p.Database, p.Measurement, p.TagCode, p.FilterString())
}
