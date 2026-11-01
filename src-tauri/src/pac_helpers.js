function isPlainHostName(h){return h.indexOf('.')<0;}
function dnsDomainIs(h,d){return h.endsWith(d);}
function localHostOrDomainIs(h,d){return h===d || (isPlainHostName(h)&&d.startsWith(h+'.'));}
function dnsResolve(h){return /^\d+\.\d+\.\d+\.\d+$/.test(h)?h:(__ips[h]||null);}
function isResolvable(h){return dnsResolve(h)!==null;}
function myIpAddress(){if(!__ips.__myIpAddress)throw new Error('local PAC address unavailable');return __ips.__myIpAddress;}
function convert_addr(ip){let p=ip.split('.');if(p.length!==4||p.some(x=>!/^\d+$/.test(x)||+x>255))throw new Error('invalid IPv4');return p.reduce((v,x)=>(v*256+(+x))>>>0,0);}
function isInNet(h,p,m){let ip=dnsResolve(h);return ip!==null && (convert_addr(ip)&convert_addr(m))===(convert_addr(p)&convert_addr(m));}
function dnsDomainLevels(h){return h.split('.').length-1;}
function shExpMatch(s,p){return new RegExp('^'+p.replace(/[.+^${}()|[\]\\]/g,'\\$&').replace(/\*/g,'.*').replace(/\?/g,'.')+'$').test(s);}
function __range(v,a,b){return a<=b?v>=a&&v<=b:v>=a||v<=b;}
function weekdayRange(){let a=Array.from(arguments),gmt=a[a.length-1]==='GMT';if(gmt)a.pop();let d=new Date(),v=gmt?d.getUTCDay():d.getDay(),days=['SUN','MON','TUE','WED','THU','FRI','SAT'];return __range(v,days.indexOf(a[0]),days.indexOf(a[1]||a[0]));}
function timeRange(){let a=Array.from(arguments),gmt=a[a.length-1]==='GMT';if(gmt)a.pop();let d=new Date(),h=gmt?d.getUTCHours():d.getHours(),m=gmt?d.getUTCMinutes():d.getMinutes(),s=gmt?d.getUTCSeconds():d.getSeconds();if(a.length===1)return h===a[0];if(a.length===2)return __range(h,a[0],a[1]);if(a.length===4)return __range(h*60+m,a[0]*60+a[1],a[2]*60+a[3]);if(a.length===6)return __range(h*3600+m*60+s,a[0]*3600+a[1]*60+a[2],a[3]*3600+a[4]*60+a[5]);throw new Error('invalid timeRange');}
function dateRange(){let a=Array.from(arguments),gmt=a[a.length-1]==='GMT';if(gmt)a.pop();let d=new Date(),day=gmt?d.getUTCDate():d.getDate(),mon=gmt?d.getUTCMonth():d.getMonth(),yr=gmt?d.getUTCFullYear():d.getFullYear(),months=['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];function val(x){return typeof x==='string'?months.indexOf(x):x;}if(a.length===1||a.length===2){let v=typeof a[0]==='string'?mon:(a[0]>31?yr:day);return __range(v,val(a[0]),val(a[a.length-1]));}if(a.length===4){if(typeof a[0]==='string')return __range(yr*12+mon,a[1]*12+val(a[0]),a[3]*12+val(a[2]));return __range(mon*32+day,val(a[1])*32+a[0],val(a[3])*32+a[2]);}if(a.length===6)return __range(Date.UTC(yr,mon,day),Date.UTC(a[2],val(a[1]),a[0]),Date.UTC(a[5],val(a[4]),a[3]));throw new Error('invalid dateRange');}
