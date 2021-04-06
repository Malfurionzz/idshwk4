# idshwk4

* The Algorithm Requirement
* make 404 statistics on orig_h
* In every 10 minutes
  * if the count of 404 response > 2
  * and if the 404 ratio > 20% (404 ratio = 404 response/all response)
  *  and if (the unique count of url response 404 / if the count of 404 response ) > 0.5
  * then output ”x.x.x.x is a scanner with y scan attemps on z urls” where
    * x.x.x.x is the orig_h, y is the count of 404 response , z is the unique count of url response 404

### 简要记录

zeek提供了`Summary Statistics`框架用于便捷地进行stream统计。

#### [SumStats::Reducer](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L44-L59)    [`record`](https://docs.zeek.org/en/master/script-reference/types.html#type-record)

`reducer` 定义了如何计算这个流

```lua
local r1 = SumStats::Reducer($stream="404", 
                                 $apply=set(SumStats::SUM));
local r2 = SumStats::Reducer($stream="Unique404Url", 
                                 $apply=set(SumStats::UNIQUE));                        
local r3 = SumStats::Reducer($stream="response", 
                                 $apply=set(SumStats::SUM));
```

- stream: [`string`](https://docs.zeek.org/en/master/script-reference/types.html#type-string)

  用于标识一个流

- apply: [`set`](https://docs.zeek.org/en/master/script-reference/types.html#type-set) [[`SumStats::Calculation`](https://docs.zeek.org/en/master/scripts/base/frameworks/sumstats/main.zeek.html?highlight=SumStats%3A%3Acreate#type-SumStats::Calculation)]

  采用的计算方式，有：SUM，UNIQUE，AVERAGE...

  .....(其他可选参数略)

#### [**SumStats::create**](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L392-L438)

用于创造一个统计实例

```lua
SumStats::create([$name = "finding scanners",
                      $epoch = 10min,
                      $reducers = set(r1,r2,r3),
                      # Provide a threshold.
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result)={
                          local s1 = result["404"];
						  local s2 = result["Unique404Url"];
						  local s3 = result["response"];
                          if(s1$sum>2 && 1.0*s1$sum / s3$sum >0.2 && 1.0*s2$unique/s1$sum>0.5){
                              print fmt("%s is a scanner with %d scan attemps on %d urls",key$host,s1$sum,s2$unique);
                          } 
                      }]);
```



- Type

  [`function`](https://docs.zeek.org/en/master/script-reference/types.html#type-function) (ss: [`SumStats::SumStat`](https://docs.zeek.org/en/master/scripts/base/frameworks/sumstats/main.zeek.html?highlight=SumStats%3A%3Acreate#type-SumStats::SumStat)) : [`void`](https://docs.zeek.org/en/master/script-reference/types.html#type-void)

#### [SumStats::SumStat](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L91-L144)

定义了统计实例的行为（epoch的时间，reducer的集合……）以及一些触发函数模板

[SumStats::observe](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L439-L504)

- Type

  [`function`](https://docs.zeek.org/en/master/script-reference/types.html#type-function) (id: [`string`](https://docs.zeek.org/en/master/script-reference/types.html#type-string), orig_key: [`SumStats::Key`](https://docs.zeek.org/en/master/scripts/base/frameworks/sumstats/main.zeek.html?highlight=SumStats%3A%3Acreate#type-SumStats::Key), obs: [`SumStats::Observation`](https://docs.zeek.org/en/master/scripts/base/frameworks/sumstats/main.zeek.html?highlight=SumStats%3A%3Acreate#type-SumStats::Observation)) : [`void`](https://docs.zeek.org/en/master/script-reference/types.html#type-void)

统计函数

- Id

  流的标识符

- Key

  值所绑定的键，详见`SumStats::Key`

- Obs

  向流发送的观察结果，详见`SumStats::Observation`

#### [SumStats::Key](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L16-L30)

- Type

  [`record`](https://docs.zeek.org/en/master/script-reference/types.html#type-record)
* str: [`string`](https://docs.zeek.org/en/master/script-reference/types.html#type-string)[`&optional`](https://docs.zeek.org/en/master/script-reference/attributes.html#attr-&optional)

  ​		一个自定义的`str`类型的键

* host: [`addr`](https://docs.zeek.org/en/master/script-reference/types.html#type-addr)[`&optional`](https://docs.zeek.org/en/master/script-reference/attributes.html#attr-&optional)

  ​		这种测量的Host，如：`c$id$orig_h`

#### [SumStats::Observation](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L34-L41)

- Type

  [`record`](https://docs.zeek.org/en/master/script-reference/types.html#type-record)
* num: [`count`](https://docs.zeek.org/en/master/script-reference/types.html#type-count)[`&optional`](https://docs.zeek.org/en/master/script-reference/attributes.html#attr-&optional)
数值统计量
* dbl: [`double`](https://docs.zeek.org/en/master/script-reference/types.html#type-double)[`&optional`](https://docs.zeek.org/en/master/script-reference/attributes.html#attr-&optional)
 浮点统计量
* str: [`string`](https://docs.zeek.org/en/master/script-reference/types.html#type-string)[`&optional`](https://docs.zeek.org/en/master/script-reference/attributes.html#attr-&optional)
字符串统计量

三种统计量均指**每次执行observe增加的值**



注：

1. 操作符`/`在两个操作数均为整数时会取整，利用`1.0*...`计算分数
2. 尽量不要用在框架中使用global。
3. 为什么[SumStats::ResultTable](https://github.com/zeek/zeek/blob/master/scripts/base/frameworks/sumstats/main.zeek#L81-L81)好像用不了？？？