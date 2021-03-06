/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package service

import (
	"fmt"

	"github.com/deckarep/golang-set"
	"github.com/google/uuid"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/model"
	"github.com/deepflowys/deepflow/server/controller/monitor"
)

func GetAnalyzers(filter map[string]interface{}) (resp []model.Analyzer, err error) {
	var response []model.Analyzer
	var analyzers []mysql.Analyzer
	var controllers []mysql.Controller
	var regions []mysql.Region
	var azs []mysql.AZ
	var azAnalyzerconns []mysql.AZAnalyzerConnection
	var vtaps []mysql.VTap

	db := mysql.Db
	if lcuuid, ok := filter["lcuuid"]; ok {
		db = db.Where("lcuuid = ?", lcuuid)
	} else if ip, ok := filter["ip"]; ok {
		db = db.Where("ip = ?", ip)
	} else if region, ok := filter["region"]; ok {
		azConns := []mysql.AZAnalyzerConnection{}
		ips := []string{}
		mysql.Db.Where("region = ?", region).Find(&azConns)
		for _, conn := range azConns {
			ips = append(ips, conn.AnalyzerIP)
		}
		db = db.Where("ip IN (?)", ips)
	}
	if states, ok := filter["states"]; ok {
		db = db.Where("state IN (?)", states)
	}
	db.Find(&analyzers)
	mysql.Db.Find(&controllers)
	mysql.Db.Find(&regions)
	mysql.Db.Find(&azs)
	mysql.Db.Find(&azAnalyzerconns)
	mysql.Db.Find(&vtaps)

	lcuuidToRegion := make(map[string]*mysql.Region)
	for i, region := range regions {
		lcuuidToRegion[region.Lcuuid] = &regions[i]
	}

	lcuuidToAz := make(map[string]*mysql.AZ)
	regionToAz := make(map[string][]*mysql.AZ)
	for i, az := range azs {
		lcuuidToAz[az.Lcuuid] = &azs[i]
		regionToAz[az.Region] = append(regionToAz[az.Region], &azs[i])
	}

	ipToAzAnalyzerCon := make(map[string][]*mysql.AZAnalyzerConnection)
	for i, conn := range azAnalyzerconns {
		ipToAzAnalyzerCon[conn.AnalyzerIP] = append(
			ipToAzAnalyzerCon[conn.AnalyzerIP],
			&azAnalyzerconns[i],
		)
	}

	analyzerIPToVtapCount := make(map[string]int)
	for _, vtap := range vtaps {
		analyzerIPToVtapCount[vtap.AnalyzerIP]++
	}

	for _, analyzer := range analyzers {
		analyzerResp := model.Analyzer{
			ID:                analyzer.ID,
			IP:                analyzer.IP,
			Name:              analyzer.Name,
			State:             analyzer.State,
			NatIP:             analyzer.NATIP,
			NatIPEnabled:      analyzer.NATIPEnabled,
			Agg:               analyzer.Agg,
			PcapDataMountPath: analyzer.PcapDataMountPath,
			CPUNum:            analyzer.CPUNum,
			MemorySize:        analyzer.MemorySize,
			Arch:              analyzer.Arch,
			ArchType:          common.GetArchType(analyzer.Arch),
			Os:                analyzer.Os,
			OsType:            common.GetOsType(analyzer.Os),
			KernelVersion:     analyzer.KernelVersion,
			VTapMax:           analyzer.VTapMax,
			SyncedAt:          analyzer.SyncedAt,
			Lcuuid:            analyzer.Lcuuid,
		}

		// state
		if analyzer.State != common.HOST_STATE_COMPLETE && analyzer.State != common.HOST_STATE_MAINTENANCE {
			analyzerResp.State = common.HOST_STATE_EXCEPTION
		} else {
			analyzerResp.State = analyzer.State
		}
		// vtap_count
		if vtapCount, ok := analyzerIPToVtapCount[analyzer.IP]; ok {
			analyzerResp.VtapCount = vtapCount
		}
		// region
		var azConns []*mysql.AZAnalyzerConnection
		azConns, in := ipToAzAnalyzerCon[analyzer.IP]
		if in {
			if region, ok := lcuuidToRegion[azConns[0].Region]; ok {
				analyzerResp.Region = region.Lcuuid
				analyzerResp.RegionName = region.Name
			}
		}
		// azs
		for _, azConn := range azConns {
			if azConn.AZ == "ALL" {
				analyzerResp.IsAllAz = true
				if cAzs, ok := regionToAz[azConn.Region]; ok {
					for _, cAz := range cAzs {
						analyzerResp.Azs = append(
							analyzerResp.Azs, model.AnalyzerAz{
								Az:     cAz.Lcuuid,
								AzName: cAz.Name,
							},
						)
					}
				}
			} else {
				analyzerResp.IsAllAz = false
				if cAz, ok := lcuuidToAz[azConn.AZ]; ok {
					analyzerResp.Azs = append(
						analyzerResp.Azs, model.AnalyzerAz{
							Az:     cAz.Lcuuid,
							AzName: cAz.Name,
						},
					)
				}
			}
		}

		response = append(response, analyzerResp)
	}
	return response, nil
}

func UpdateAnalyzer(
	lcuuid string, analyzerUpdate map[string]interface{}, m *monitor.AnalyzerCheck,
	cfg *config.ControllerConfig,
) (resp model.Analyzer, err error) {
	var analyzer mysql.Analyzer
	var dbUpdateMap = make(map[string]interface{})

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return model.Analyzer{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("update analyzer (%s) config %v", analyzer.Name, analyzerUpdate)

	// ?????????????????????????????????
	if _, ok := analyzerUpdate["VTAP_MAX"]; ok {
		vtapMax := int(analyzerUpdate["VTAP_MAX"].(float64))
		mysql.Db.Model(analyzer).Update("vtap_max", vtapMax)

		// TODO: ????????????????????????????????????????????????????????????????????????????????????????????????
		if vtapMax < analyzer.VTapMax {
			vtaps := []mysql.VTap{}
			updateVTapLcuuids := []string{}
			mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Find(&vtaps)
			if len(vtaps) > vtapMax {
				for i := vtapMax; i < len(vtaps)-1; i++ {
					updateVTapLcuuids = append(updateVTapLcuuids, vtaps[i].Lcuuid)
				}
				vtapDb := mysql.Db.Model(&mysql.VTap{})
				vtapDb = vtapDb.Where("lcuuid IN (?)", updateVTapLcuuids)
				vtapDb.Update("analyzer_ip", "")
				m.TriggerReallocAnalyzer("")
			}
		}
	}

	// ????????????????????????
	if _, regionUpdate := analyzerUpdate["REGION"]; regionUpdate {
		var azControllerConns []mysql.AZControllerConnection
		// ????????????????????????????????????????????????????????????????????????
		mysql.Db.Where("region = ?", analyzerUpdate["REGION"]).Find(&azControllerConns)
		if len(azControllerConns) == 0 {
			return model.Analyzer{}, NewError(common.INVALID_POST_DATA, "no controller in same region")
		}
	}
	if _, ok := analyzerUpdate["AZS"]; ok {
		azs := analyzerUpdate["AZS"].([]interface{})
		if len(azs) > cfg.Spec.AZMaxPerServer {
			return model.Analyzer{}, NewError(
				common.INVALID_POST_DATA,
				fmt.Sprintf(
					"max az num associated analyzer is (%d)", cfg.Spec.AZMaxPerServer,
				),
			)
		}
		// ?????????????????????????????????????????????????????????????????????????????????????????????
		var azAnalyzerConns []mysql.AZAnalyzerConnection
		var addConns []mysql.AZAnalyzerConnection
		var dbAzs []mysql.AZ
		var analyzerRegion string
		var oldAzs = mapset.NewSet()
		var newAzs = mapset.NewSet()
		var delAzs = mapset.NewSet()
		var addAzs = mapset.NewSet()

		mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Find(&azAnalyzerConns)
		if len(azAnalyzerConns) > 0 {
			analyzerRegion = azAnalyzerConns[0].Region
		} else {
			analyzerRegion = common.DEFAULT_REGION
		}

		for _, conn := range azAnalyzerConns {
			oldAzs.Add(conn.AZ)
		}

		// ?????????????????????
		// - delAzs??????
		//   - ????????????????????????????????????delAzs=??????????????????????????????
		//   - ??????delAzs=??????????????????
		// - addAzs??????
		//   - ????????????????????????????????????addAzs=ALL
		//   - ??????addAzs=??????????????????
		// ????????????????????????
		// - delAzs=oldAzs-newAzs
		// - addAzs=newAzs-oldAzs
		if _, regionUpdate := analyzerUpdate["REGION"]; regionUpdate {
			if oldAzs.Contains("ALL") {
				mysql.Db.Where("region = ?", analyzerRegion).Find(&dbAzs)
				for _, az := range dbAzs {
					delAzs.Add(az.Lcuuid)
				}
			} else {
				delAzs = oldAzs
			}

			if _, azUpdate := analyzerUpdate["IS_ALL_AZ"]; azUpdate {
				if analyzerUpdate["IS_ALL_AZ"].(bool) {
					addAzs.Add("ALL")
				}
			}
			if !addAzs.Contains("ALL") {
				for _, az := range azs {
					addAzs.Add(az)
				}
			}
			analyzerRegion = analyzerUpdate["REGION"].(string)
		} else {
			for _, az := range azs {
				newAzs.Add(az)
			}
			delAzs = oldAzs.Difference(newAzs)
			addAzs = newAzs.Difference(oldAzs)
		}

		// ??????delAzs, ??????azAnalyzerconn
		var azCondition []string
		if oldAzs.Contains("ALL") {
			azCondition = append(azCondition, "ALL")
		} else {
			for _, az := range delAzs.ToSlice() {
				azCondition = append(azCondition, az.(string))
			}
		}
		mysql.Db.Where("analyzer_ip = ? AND az IN (?)", analyzer.IP, azCondition).Delete(mysql.AZAnalyzerConnection{})

		// ??????addAzs, ??????azAnalyzerconn
		for _, az := range addAzs.ToSlice() {
			aConn := mysql.AZAnalyzerConnection{}
			aConn.Region = analyzerRegion
			aConn.AZ = az.(string)
			aConn.AnalyzerIP = analyzer.IP
			aConn.Lcuuid = uuid.New().String()
			addConns = append(addConns, aConn)
		}
		mysql.Db.Create(&addConns)

		// ??????delAzs???????????????, ??????????????????IP???????????????????????????????????????
		vtapDb := mysql.Db.Model(&mysql.VTap{})
		vtapDb = vtapDb.Where("az IN (?)", delAzs.ToSlice())
		vtapDb = vtapDb.Where("analyzer_ip = ?", analyzer.IP)
		vtapDb.Update("analyzer_ip", "")
		m.TriggerReallocAnalyzer("")
	}

	// ????????????
	if _, ok := analyzerUpdate["STATE"]; ok {
		dbUpdateMap["state"] = analyzerUpdate["STATE"]
		// ?????????????????????????????????/????????????????????????????????????????????????????????????
		state := int(analyzerUpdate["STATE"].(float64))
		if state == common.HOST_STATE_MAINTENANCE || state == common.HOST_STATE_EXCEPTION {
			m.TriggerReallocAnalyzer(analyzer.IP)
		}
	}

	// ??????nat_ip
	if _, ok := analyzerUpdate["NAT_IP"]; ok {
		// TODO: ??????????????????????????????????????????
		dbUpdateMap["nat_ip"] = analyzerUpdate["NAT_IP"]
	}

	// ????????????????????????
	if _, ok := analyzerUpdate["AGG"]; ok {
		dbUpdateMap["agg"] = analyzerUpdate["AGG"]
	}

	// ??????analyzer DB
	mysql.Db.Model(&analyzer).Updates(dbUpdateMap)

	response, _ := GetAnalyzers(map[string]interface{}{"lcuuid": lcuuid})
	return response[0], nil
}

func DeleteAnalyzer(lcuuid string, m *monitor.AnalyzerCheck) (resp map[string]string, err error) {
	var analyzer mysql.Analyzer
	var vtapCount int64

	if ret := mysql.Db.Where("lcuuid = ?", lcuuid).First(&analyzer); ret.Error != nil {
		return map[string]string{}, NewError(common.RESOURCE_NOT_FOUND, fmt.Sprintf("analyzer (%s) not found", lcuuid))
	}

	log.Infof("delete analyzer (%s)", analyzer.Name)

	mysql.Db.Where("analyzer_ip = ?", analyzer.IP).Count(&vtapCount)
	if vtapCount > 0 {
		return map[string]string{}, NewError(common.INVALID_POST_DATA, fmt.Sprintf("analyzer (%s) is being used by vtap", lcuuid))
	}

	mysql.Db.Delete(mysql.AZAnalyzerConnection{}, "analyzer_ip = ?", analyzer.IP)
	mysql.Db.Delete(&analyzer)

	// ????????????????????????????????????????????????
	m.TriggerReallocAnalyzer(analyzer.IP)

	return map[string]string{"LCUUID": lcuuid}, nil
}
