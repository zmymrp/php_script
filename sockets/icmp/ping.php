<?php
if(isset($_GET['ip']) && !empty($_GET['ip'])){
	$code = ping($_GET['ip'], $msg);
}else{
	$code = 1;
	$msg = 'Request GET to submit IP';
}
$response = array(
	'code' => $code,
	'msg' => $msg
);
header('Content-Type: application/json');
die(json_encode($response));
function ping($host, &$msg){
	$g_icmp_error = NULL;
	$write = NULL;
	$except = NULL; //初始化所需变量
	$package  = chr(8).chr(0); //模式8 0
	$package .= chr(0).chr(0); //置零校验
	$package .= "R"."C"; //ID
	$package .= chr(0).chr(1); //序列号
	for($i = strlen($package); $i < 64; $i++){
		$package .= chr(0);
	}
	$tmp = unpack("n*", $package); //把数据16位一组放进数组里
	$sum = array_sum($tmp); //求和
	$sum = ($sum >> 16) + ($sum & 0xFFFF); //结果右移十六位 加上结果与0xFFFF做AND运算
	$sum = $sum + ($sum >> 16); //结果加上结果右移十六位
	$sum = ~ $sum; //做NOT运算
	$checksum = pack("n*", $sum); //打包成2字节
	$package[2] = $checksum[0];
	$package[3] = $checksum[1]; //填充校验和
	$socket = socket_create(AF_INET, SOCK_RAW, getprotobyname('icmp')); //创建原始套接字
	if($socket === FALSE){
		$msg = "socket_create(): " . socket_strerror(socket_last_error());
		return socket_last_error();
	}
	$start = microtime(); //记录开始时间
	socket_sendto($socket, $package, strlen($package), 0, $host, 0); //发送数据包
	$read = array($socket); //初始化socket
	$select = socket_select($read, $write, $except, 5);
	if($select === FALSE){
		$icmpError = "socket_select(): " . socket_strerror(socket_last_error());
		$code = socket_last_error();
		socket_close($socket);
	}else if($select === 0){
		$icmpError = "Request timeout";
		$code = -1;
		socket_close($socket);
	}
	if($icmpError !== NULL){
		$msg = $icmpError;
		return $code;
	}
	socket_recvfrom($socket, $recv, 65535, 0, $host, $port); //接受回传数据
	/*回传数据处理*/
	$end = microtime(); //记录结束时间
	$recv = unpack("C*", $recv);
	$length = count($recv) - 20; //包长度 减去20字节IP报头
	$ttl = $recv[9]; //ttl
	$icmp_type = $recv[21]; //Type
	$icmp_code = $recv[22]; //Code
	$seq = $recv[28]; //序列号
	$duration = round(($end - $start) * 1000, 3); //计算耗费的时间
	socket_close($socket); //关闭socket
	if($icmp_type === 0 && $icmp_code === 0){
		$msg = "{$length} bytes from {$host}: icmp_seq={$seq} ttl={$ttl} time={$duration}ms"; //输出结果
		return 0;
	}
	$result_code = $icmp_type . '_' . $icmp_code;
	switch($result_code){
		case '3_1':
			$msg = "{$length} bytes from {$host}: Host Unreachable type={$icmp_type} code={$icmp_code}";
			break;
		default:
			$msg = "{$length} bytes from {$host}: Other error type={$icmp_type} code={$icmp_code}";
			break;
	}
	return -2;
}
