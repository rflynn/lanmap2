<?php

error_reporting(E_ALL);

/**
 * merge address records
 */
function merge_addrs($key, $a, $b)
{
  assert(is_array($a));
  assert(is_array($b));
  $x = array();
  foreach ($a as $y) {
    if ($key != $y["from_"] && !@isset($x[$y["from_"]]))
      $x[$y["from_"]] = $y;
    else if ($key != $y["to_"] && !@isset($x[$y["to_"]]))
      $x[$y["to_"]] = $y;
  }
  foreach ($b as $y) {
    if ($key != $y["from_"] && !@isset($x[$y["from_"]]))
      $x[$y["from_"]] = $y;
    else if ($key != $y["to_"] && !@isset($x[$y["to_"]]))
      $x[$y["to_"]] = $y;
  }
  #echo "key=$key x=".print_r($x,1);
  return $x;
}

/**
 * Group lists containing matching elements;
 * Perform the following transformation:
 *  [[a,b],[b,c],[c,d],[x,y]] -> [[a,b,c,d], [x,y]]
 */
function conglomerate($set)
{
  do {
    $merged = 0;
    reset($set);
    while (list($k,$v) = each($set)) {
      var_dump($k);
      var_dump($v);
      foreach (array_keys($v) as $kk) {
        if ($k != $kk && isset($set[$kk])) {
          $set[$k] = array_merge($set[$k], $set[$kk]);
          unset($set[$kk]);
          $merged++;
        }
      }
    }
  } while ($merged > 0);
  #echo "set: "; var_dump($set);
  do {
    $merged = 0;
    reset($set);
    while (list($k,$v) = each($set)) {
      #echo "k=$k...\n";
      while (list($kk,$vv) = each($v)) {
        #echo " kk=$kk...\n";
        $copy = $set;
        while (list($kkk,$vvv) = each($copy)) {
          #echo "  kkk=$kkk...\n";
          if (@isset($set[$kkk][$kk]) && $k != $kkk) {
            #echo "   $k@$kk <-> $kkk@$kk\n";
            #echo "merging k=".print_r($set[$k],1);
            #echo "merging kkk=".print_r($set[$kkk],1);
            #$set[$k] = array_merge($set[$k], $set[$kkk]);
            $set[$k] = merge_addrs($k, array_values($set[$k]),
                                       array_values($set[$kkk]));
            #echo "merged=".print_r($set[$k],1);
            unset($set[$kkk]);
            $merged++;
          }
        }
      }
    }
  } while ($merged > 0);
  return $set;
}

function test_conglom1()
{
  $x = array(
    "a" => array("b"=>0,"c"=>1),
    "c" => array("d"=>2),
    "d" => array("e"=>3,"f"=>4),
    "f" => array(),
    "x" => array("y"=>5));
  $expected = array(
    "a" => array("b"=>0,"c"=>1,"d"=>2,"e"=>3,"f"=>4),
    "x" => array("y"=>5));
  #echo "before: " . print_r($x, 1);
  $x = conglomerate($x);
  #echo "after: " . print_r($x, 1);
  assert($x === $expected);
}

function test_conglom2()
{
  $x = array(
    "a" => array("b"=>0),
    "c" => array("b"=>1));
  $expected = array(
    "a" => array("b"=>array(0,1)));
  echo "before2: " . print_r($x, 1);
  $x = conglomerate($x);
  echo "after2: " . print_r($x, 1);
  assert($x === $expected);
}

function test_conglomerate()
{
  test_conglom1();
  test_conglom2();
}

#test_conglomerate();

?>
