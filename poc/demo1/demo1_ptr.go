package demo1

import(
  "log"
  "fmt"
  "database/sql"
  "sort"
  "unsafe"

  _ "github.com/go-sql-driver/mysql"
  "github.com/emirpasic/gods/utils"
  rbt "github.com/emirpasic/gods/trees/redblacktree"

  "dbproj_poc/config"
)

type combinedRowPtr struct {
  left    unsafe.Pointer
  right   unsafe.Pointer
}

type groupRowPtr struct {
  groupKey
  data                  []*combinedRowPtr
  r2_func_count         int
  ida_func_count        int
  common_records_count  int
}

func RunPtr(){
  log.SetFlags(log.LstdFlags | log.Lshortfile)
  log.Println("Demo 1 start.")

  // connect to db
  log.Println("Connect to DB.")
  conn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
                config.USERNAME,
                config.PASSWORD,
                config.ADDR,
                config.PORT,
                config.DEMO1_DB)
  db, err := sql.Open("mysql", conn)
  if err != nil {
    log.Fatal(err)
  }

  // select the first table
  log.Println("Select the first table.")
  stmt, err := db.Prepare("SELECT ID, `Group`, Malicious FROM Samples WHERE Valid=True AND `Group`=?")
  if err != nil {
    log.Fatal(err)
  }
  rows, err := stmt.Query(GROUP)

  samples := make([]sample, 0, 0)
  for rows.Next() {
    var tmpSample sample
    err = rows.Scan(&tmpSample.id, &tmpSample.group, &tmpSample.mal)
    if err != nil {
      log.Fatal(err)
    }
    samples = append(samples, tmpSample)
  }

  // build rbtree for samples
  samplesRBT := rbt.NewWith(func(a, b interface{}) int {
    return utils.IntComparator(a, b)
  })
  for idx:=0; idx<len(samples); idx++ {
    if subSamples, exists := samplesRBT.Get(samples[idx].id); !exists {
      samplesRBT.Put(samples[idx].id, [](*sample){&samples[idx]})
    } else {
      samplesRBT.Put(samples[idx].id, append(subSamples.([](*sample)), &samples[idx]))
    }
  }

  PrintMemUsage()

  // select the second table
  log.Println("Select and join the second table.")
  rows, err = db.Query("SELECT ID, SID, Addr FROM r2_func")
  if err != nil {
    log.Fatal(err)
  }

  combinedRows := make([]combinedRowPtr, 0, 0)
  funcInfos := make([]funcInfo, 0, 0)
  rowsCount := 0
  for rows.Next() {
    rowsCount += 1
    // read func
    var tmpFuncInfo funcInfo
    err = rows.Scan(&tmpFuncInfo.id, &tmpFuncInfo.sid, &tmpFuncInfo.addr)
    if err != nil {
      log.Fatal(err)
    }

    // inner join
    /*
    saved := false
    for idx:=0; idx<len(samples); idx++ {
      if samples[idx].id == tmpFuncInfo.sid {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: &samples[idx], right: &funcInfos[len(funcInfos)-1]})
      }
    }
    */
    if subSamples, exists := samplesRBT.Get(tmpFuncInfo.sid); exists {
      saved := false
      for _, sampleAddr := range(subSamples.([](*sample))) {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRowPtr{left: unsafe.Pointer(sampleAddr), right: unsafe.Pointer(&funcInfos[len(funcInfos)-1])})
      }
    }
  }

  // delete samplesRBT
  samplesRBT.Clear()


  // build rbtree for joined table
  tableRBT := rbt.NewWith(func(a, b interface{}) int {
    return utils.IntComparator(a, b)
  })
  for idx:=0; idx<len(combinedRows); idx++ {
    id := (*sample)(combinedRows[idx].left).id
    if subRows, exists := tableRBT.Get(id); !exists {
      tableRBT.Put(id, [](*combinedRowPtr){&combinedRows[idx]})
    } else {
      tableRBT.Put(id, append(subRows.([](*combinedRowPtr)), &combinedRows[idx]))
    }
  }

  PrintMemUsage()

  // select the third table
  log.Println("Select and join the third table.")
  rows, err = db.Query("SELECT ID, SID, Addr FROM ida_func")
  if err != nil {
    log.Fatal(err)
  }

  curTable := combinedRows[:]
  leftUsed := make(map[*combinedRowPtr]struct{})
  for rows.Next() {
    // read func
    var tmpFuncInfo funcInfo
    err = rows.Scan(&tmpFuncInfo.id, &tmpFuncInfo.sid, &tmpFuncInfo.addr)
    if err != nil {
      log.Fatal(err)
    }

    // left join
    /*
    saved := false
    for idx:=0; idx<len(curTable); idx++ {
      if curTable[idx].left.(*sample).id == tmpFuncInfo.sid {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRow{left: &curTable[idx], right: &funcInfos[len(funcInfos)-1]})
        leftUsed[idx] = struct{}{}
      }
    }
    */
    if subRows, exists := tableRBT.Get(tmpFuncInfo.sid); exists {
      saved := false
      for _, combinedRowAddr := range(subRows.([](*combinedRowPtr))) {
        if !saved {
          funcInfos = append(funcInfos, tmpFuncInfo)
          saved = true
        }
        combinedRows = append(combinedRows, combinedRowPtr{left: unsafe.Pointer(combinedRowAddr), right: unsafe.Pointer(&funcInfos[len(funcInfos)-1])})
        leftUsed[combinedRowAddr] = struct{}{}
      }
    }
  }

  // add not paired left data
  for idx:=0; idx<len(curTable); idx++ {
    if _, exists := leftUsed[&curTable[idx]]; !exists{
      combinedRows = append(combinedRows, combinedRowPtr{left: unsafe.Pointer(&curTable[idx]), right: nil})
    }
  }

  // delete tableRBT
  tableRBT.Clear()

  // update new table
  curTable = combinedRows[len(curTable):]
  log.Printf("Found %d rows.\n", len(curTable))

  PrintMemUsage()

  // group table
  log.Println("Group tables by id, group, and malicious.")
  // build rbtree for curTable
  tableRBT = rbt.NewWith(func(a, b interface{}) int {
    if a.(groupKey).id < b.(groupKey).id {
      return -1
    } else if a.(groupKey).id == b.(groupKey).id {
      if a.(groupKey).group < b.(groupKey).group {
        return -1
      } else if a.(groupKey).group == b.(groupKey).group {
        if a.(groupKey).mal == b.(groupKey).mal {
          return 0
        } else if a.(groupKey).mal {
          return 1
        } else {
          return -1
        }
      } else {
        return 1
      }
    } else {
      return 1
    }
  })

  groupRows := make([]groupRowPtr, 0, 0)
  for idx:=0; idx<len(curTable); idx++ {
    tmpID := (*sample)((*combinedRowPtr)(curTable[idx].left).left).id
    tmpGroup := (*sample)((*combinedRowPtr)(curTable[idx].left).left).group
    tmpMal := (*sample)((*combinedRowPtr)(curTable[idx].left).left).mal
    key := groupKey{id: tmpID, group: tmpGroup, mal: tmpMal}

    if groupNode, exists := tableRBT.Get(key); !exists {
      groupRows = append(groupRows, groupRowPtr{
        groupKey:   groupKey{
          id:     tmpID,
          group:  tmpGroup,
          mal:    tmpMal,
        },
        data:   make([](*combinedRowPtr), 0, 0),
      })
      nodeRef := &groupRows[len(groupRows)-1]
      nodeRef.data = append(nodeRef.data, &curTable[idx])
      tableRBT.Put(key, nodeRef)
    } else {
      nodeRef := groupNode.(*groupRowPtr)
      nodeRef.data = append(nodeRef.data, &curTable[idx])
    }
  }

  log.Printf("Group into %d rows.\n", len(groupRows))

  PrintMemUsage()

  // calculate function counts
  log.Println("Calculate function counts.")
  for idx:=0; idx<len(groupRows); idx++ {
    ida_set := make(map[int]struct{})
    r2_set := make(map[int]struct{})
    common_set := make(map[int]struct{})

    for _, rowRef := range(groupRows[idx].data) {
      r2_set[(*funcInfo)((*combinedRowPtr)(rowRef.left).right).id] = struct{}{}
      if rowRef.right != nil {
        ida_set[(*funcInfo)(rowRef.right).id] = struct{}{}
        if (*funcInfo)(rowRef.right).addr == (*funcInfo)((*combinedRowPtr)(rowRef.left).right).addr {
          common_set[(*funcInfo)((*combinedRowPtr)(rowRef.left).right).id] = struct{}{}
        }
      }
    }

    groupRows[idx].ida_func_count = len(ida_set)
    groupRows[idx].r2_func_count = len(r2_set)
    groupRows[idx].common_records_count = len(common_set)
  }

  PrintMemUsage()


  // sort
  log.Println("Sort by malicious and ida_func_count.")

  sort.Slice(groupRows, func(i, j int) bool {
    if groupRows[i].groupKey.mal != groupRows[j].groupKey.mal {
      return !groupRows[i].groupKey.mal
    }
    return groupRows[i].ida_func_count < groupRows[j].ida_func_count
  })

  log.Println("Task finished.")

  PrintMemUsage()

  // Print
  for idx:=0; idx<len(groupRows); idx++ {
    fmt.Println(groupRows[idx].id, groupRows[idx].group, groupRows[idx].mal, groupRows[idx].ida_func_count, groupRows[idx].r2_func_count, groupRows[idx].common_records_count)
  }
}
