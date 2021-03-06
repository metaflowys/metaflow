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

package controller

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/deepflowys/deepflow/server/libs/logger"

	"github.com/gin-gonic/gin"
	logging "github.com/op/go-logging"
	yaml "gopkg.in/yaml.v2"

	"github.com/deepflowys/deepflow/server/controller/common"
	"github.com/deepflowys/deepflow/server/controller/config"
	"github.com/deepflowys/deepflow/server/controller/db/mysql"
	"github.com/deepflowys/deepflow/server/controller/db/redis"
	"github.com/deepflowys/deepflow/server/controller/genesis"
	"github.com/deepflowys/deepflow/server/controller/manager"
	"github.com/deepflowys/deepflow/server/controller/monitor"
	"github.com/deepflowys/deepflow/server/controller/monitor/license"
	"github.com/deepflowys/deepflow/server/controller/recorder"
	"github.com/deepflowys/deepflow/server/controller/router"
	"github.com/deepflowys/deepflow/server/controller/statsd"
	"github.com/deepflowys/deepflow/server/controller/tagrecorder"
	"github.com/deepflowys/deepflow/server/controller/trisolaris"
	trouter "github.com/deepflowys/deepflow/server/controller/trisolaris/server/http"

	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/grpc/healthcheck"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/grpc/synchronize"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/http/cache"
	_ "github.com/deepflowys/deepflow/server/controller/trisolaris/services/http/upgrade"
)

var log = logging.MustGetLogger("controller")

type Controller struct{}

func Start(configPath string) {
	flag.Parse()
	logger.EnableStdoutLog()

	serverCfg := config.DefaultConfig()
	serverCfg.Load(configPath)
	cfg := &serverCfg.ControllerConfig
	logger.EnableFileLog(cfg.LogFile)
	logLevel, _ := logging.LogLevel(cfg.LogLevel)
	logging.SetLevel(logLevel, "")
	bytes, _ := yaml.Marshal(cfg)
	log.Info("============================== Launching YUNSHAN DeepFlow Controller ==============================")
	log.Infof("controller config:\n%s", string(bytes))

	// ?????????MySQL
	isMasterController, _, err := common.IsMasterController()
	if err == nil && isMasterController {
		ok := mysql.Migrate(cfg.MySqlCfg)
		if !ok {
			time.Sleep(time.Second) // TODO add sleep before all os.Exit
			os.Exit(0)
		}
	}

	mysql.Db = mysql.Gorm(cfg.MySqlCfg)
	if mysql.Db == nil {
		log.Error("connect mysql failed")
		os.Exit(0)
	}

	// ?????????Redis
	if cfg.RedisCfg.Enabled {
		err := redis.InitRedis(cfg.RedisCfg)
		if err != nil {
			log.Error("connect redis failed")
		}
	}

	// start statsd
	err = statsd.NewStatsdMonitor(cfg.StatsdCfg)
	if err != nil {
		log.Error("cloud statsd connect telegraf failed")
		return
	}

	// ??????genesis
	g := genesis.NewGenesis(cfg.GenesisCfg)
	g.Start()

	// ??????resource manager
	// ???????????????????????????cloud???recorder
	m := manager.NewManager(cfg.ManagerCfg)
	m.Start()

	// ??????trisolaris
	t := trisolaris.NewTrisolaris(&cfg.TrisolarisCfg, mysql.Db)
	go t.Start()

	tr := tagrecorder.NewTagRecorder(*cfg)
	controllerCheck := monitor.NewControllerCheck(cfg.MonitorCfg)
	analyzerCheck := monitor.NewAnalyzerCheck(cfg.MonitorCfg)
	vtapLicenseAllocation := license.NewVTapLicenseAllocation(cfg.MonitorCfg)
	go func() {
		// ???????????????????????????master controller
		// ???master controller???????????????goroutine
		// - tagrecorder
		// - ??????????????????????????????
		// - license???????????????
		// ?????????????????????????????????master controller??????????????????????????????????????????goroutine?????????

		// ???????????????????????????????????????master controller
		if cfg.TrisolarisCfg.NodeType != "master" {
			return
		}
		masterController := ""
		for range time.Tick(time.Minute) {
			isMasterController, curMasterController, err := common.IsMasterController()
			if err != nil {
				continue
			}
			if masterController != curMasterController {
				log.Infof("current master controller is %s", curMasterController)
				masterController = curMasterController
				if isMasterController {
					// ??????tagrecorder
					tr.Start()

					// ???????????????
					controllerCheck.Start()

					// ??????????????????
					analyzerCheck.Start()

					// license???????????????
					vtapLicenseAllocation.Start()

					// ???????????????????????????
					recorder.CleanDeletedResources(
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceCleanInterval),
						int(cfg.ManagerCfg.TaskCfg.RecorderCfg.DeletedResourceRetentionTime),
					)
				}
			}
		}
	}()

	// register router
	r := gin.Default()
	router.DebugRouter(r, m, g)
	router.HealthRouter(r)
	router.ControllerRouter(r, controllerCheck, cfg)
	router.AnalyzerRouter(r, analyzerCheck, cfg)
	router.VtapRouter(r)
	router.VtapGroupRouter(r, cfg)
	router.DataSourceRouter(r, cfg)
	router.DomainRouter(r, cfg.GenesisCfg.GRPCServerPort)
	router.VTapGroupConfigRouter(r)
	router.VTapInterface(r, cfg)
	trouter.RegistRouter(r)
	if err := r.Run(fmt.Sprintf(":%d", cfg.ListenPort)); err != nil {
		log.Errorf("startup service failed, err:%v\n", err)
		os.Exit(0)
	}
}
