rule FTCode_20191031{
  meta:
    description = "FTCode zip dropper"
    author = "br4indump"
    last_updated = "2019-11-03"
    tlp = "white"
    category = "informational"
  
  strings:
    $a1 = {74 61 72 69 66 66 65}
    $a2 = {2E 76 62 73 55}
    
  condition:
    all of them
}
