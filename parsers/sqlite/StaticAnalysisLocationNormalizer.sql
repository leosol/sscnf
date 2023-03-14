create view vw_static_analysis
as
select 
	APK,
	APKPackage,
	ClassToSearch, 
	MethodToSearch,
	FoundAtClass,
	FoundAtMethod,
	CASE MethodToSearch
		 WHEN 'void .*\(.*android.location.LocationRequest.*\)' THEN 'REF_REQ_OBJ'
		 WHEN 'void requestLocationUpdates\(.*\)' THEN 'REQ_LOCATION_METHOD_NAME'
		 WHEN 'void requestLocationUpdates(java.lang.String,android.location.LocationRequest,java.util.concurrent.Executor,android.location.LocationListener)' THEN 'REQ_LOC_UPDATE'
		 WHEN 'com.google.android.gms.tasks.Task requestLocationUpdates(com.google.android.gms.location.LocationRequest,android.app.PendingIntent)' THEN 'REQ_LOC_UPDATE'
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.app.PendingIntent)' THEN 'REQ_LOC_UPDATE_WITH_PARAM'
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener)' THEN 'REQ_LOC_UPDATE_WITH_PARAM'
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener,android.os.Looper)' THEN 'REQ_LOC_UPDATE_WITH_PARAM'
		 WHEN 'void requestSingleUpdate\(.*\)' THEN 'SINGLE_REQUEST'
		 WHEN 'com.google.android.gms.location.LocationRequest setExpirationDuration(long)' THEN 'MAX_WAIT_FOR_LOCATION_MILLIS'
		 WHEN 'com.google.android.gms.location.LocationRequest setInterval(long)' THEN 'RECURRENCE_FOR_LOCATION_MILLIS'
		 WHEN 'com.google.android.gms.location.LocationRequest setNumUpdates(int)' THEN 'MAX_RECEIVED_LOCATIONS'
		 WHEN 'com.google.android.gms.location.LocationRequest setPriority(int)' THEN 'PRIORTY_ACCURATE_LP_PASSIVE'
		 ELSE 'UNKNOWN' 
	END AS LOC_REQ_INFO,
	CASE MethodToSearch
		 WHEN 'com.google.android.gms.location.LocationRequest setExpirationDuration(long)' THEN Arguments0
		 ELSE '' 
	END AS MAX_WAIT_FOR_LOCATION_MILLIS,
	CASE MethodToSearch
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.app.PendingIntent)' THEN Arguments0
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener)' THEN Arguments0
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener,android.os.Looper)' THEN Arguments0
		 ELSE '' 
	END AS MIN_TIME_BTW_UPDATES_MILLIS,
	CASE MethodToSearch
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.app.PendingIntent)' THEN Arguments1
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener)' THEN Arguments1
		 WHEN 'void requestLocationUpdates(java.lang.String,long,float,android.location.LocationListener,android.os.Looper)' THEN Arguments1
		 ELSE '' 
	END AS MIN_DISTANCE_BTW_UPDATES_METERS,
	CASE MethodToSearch
		 WHEN 'void requestSingleUpdate\(.*\)' THEN 'YES'
		 ELSE '' 
	END AS IS_SINGLE_REQUEST,
	CASE MethodToSearch
		 WHEN 'com.google.android.gms.location.LocationRequest setInterval(long)' THEN Arguments0
		 ELSE '' 
	END AS REPEAT_INTERVAL,
	CASE MethodToSearch
		 WHEN 'com.google.android.gms.location.LocationRequest setNumUpdates(int)' THEN Arguments0
		 ELSE '' 
	END AS NUM_UPDATES,
	CASE MethodToSearch
		 WHEN 'com.google.android.gms.location.LocationRequest setPriority(int)' THEN Arguments0
		 ELSE '' 
	END AS PRIORITY
from myAndroidInspect_csv