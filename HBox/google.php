#!/usr/bin/php
<?php
set_time_limit(0);
error_reporting(E_ERROR);
define("_RESULT",'result.txt');
function geturl($keywords, $page, $num)
{    
        $page = ($page - 1) * 10;     
        $content = file_get_contents("http://www.google.com.lol/search?sclient=psy-ab&hl=en&start=$page&source=hp&q=$keywords&pbx=1&oq=$keywords&num=$num&aq=f&aqi=g4");            
        $preg = '/<h3\s*class="r"\s*>.*/im';                     
        preg_match_all($preg, $content, $m);      
        preg_match_all('/<a(.*?)>(.*?)/', $m[0][0], $ms);
      
        $list = array();      
        foreach ($ms[1] as $link)
        {
                preg_match('/http:\/\/[a-zA-Z0-9._-]*/', $link, $matches);              
                if (!empty($matches[0]))
                {
                        $list[] = $matches[0];
                }
        }
        $list = array_unique($list);
        return $list;
}
 
 
$GOOGLEDORK = "inurl:news.php;
echo "Result file [Enter for None]: \r\n";
$result = trim(fgets(STDIN));
if($result==NULL){$result=_RESULT;}
if(file_exists("$result")){
  @unlink("$result");
  echo "Clear Cache ...\r\n";
  }
$page = 20;
$num = 100;
for ($i=1;$i<=$page;$i++)
{      
        $url = geturl($GOOGLEDORK, $i, $num);
        print_r('[+] Page: '.$i.' Results Count: '.count($url)."\r\n");      
            foreach ($url as $u)
            {
               #print_r($u."\r\n");
              @$fp=@fopen('tmp','a');
              @fwrite($fp,$u."\r\n");
              @fclose($fp);
              
            }
} 
                $new_filename="$result";           
                $file=file('tmp');
                $array=preg_replace('/($\s*$)|(^\s*^)/m','',$file);
                foreach ($array as $key=>$r){
      
                     $array[$key]=trim("$r");
      
                    }
               $names=dirname(__FILE__).DIRECTORY_SEPARATOR.$new_filename;
               $new_array=array_values(array_unique($array));
              
        if(file_put_contents("$new_filename",join("\r\n",$new_array)))
           
                {
                    echo "Get Subdomain Success!\r\n\r\n";
                                        usleep(100000);
                                        echo "Save  To:\r\n". $names."\r\n\r\n";
                                        
                                       
                                                if(file_exists('tmp'))
                        {
                            @unlink('tmp');
                            echo "Clear Cache ...\r\n\r\n";
                                                       
                         }
                    }else {
                                       echo "\r\n[!] Failed! Connect Google Error!\r\n ";
                                       echo "\r\n[-] Plase Proxy...\r\n";
                                      }
              
               
               exit;
?>
