"""CTE to CE migration script.

Run this script after upgrading the Core and UI containers from CTE 1.0.0/2.0.x
to CE 3.0.0.

- When upgrading containers, make sure to not delete the `mongodb` container.
- Explicitly specify names of the `core` and `ui` containers to remove them as
  without using the names all 3 of the containers will be removed. 


> docker-compose rm core ui
> docker-compose pull core ui
> docker-compose up -d
> docker cp migrate.py core:/opt
> docker exec -ti core python /opt/migrate.py
"""

from netskope.common.utils import DBConnector, Collections

connector = DBConnector()
# update aging task for CTE
connector.collection(Collections.SCHEDULES).update_one(
    {"name": "INTERNAL INDICATOR AGING TASK"},
    {"$set": {"task": "cte.age_indicators"}},
)

# add ITSM tasks
connector.collection(Collections.SCHEDULES).update_one(
    {"name": "INTERNAL UNMUTE TASK"},
    {
        "$set": {
            "_cls": "PeriodicTask",
            "name": "INTERNAL UNMUTE TASK",
            "enabled": True,
            "args": [],
            "task": "itsm.unmute",
            "interval": {"every": 5, "period": "minutes"},
        }
    },
    upsert=True,
)

connector.collection(Collections.SCHEDULES).update_one(
    {"name": "INTERNAL ALERT CLEANUP TASK"},
    {
        "$set": {
            "_cls": "PeriodicTask",
            "name": "INTERNAL ALERT CLEANUP TASK",
            "enabled": True,
            "args": [],
            "task": "itsm.delete_alerts",
            "interval": {"every": 12, "period": "hours"},
        }
    },
    upsert=True,
)

connector.collection(Collections.SETTINGS).update_one(
    {},
    {
        "$set": {
            "databaseVersion": "1.3.0",
            "alertCleanup": 7,
            "platforms": {"cte": True, "itsm": False},
        }
    },
)

connector.collection(Collections.SCHEDULES).update_many(
    {"task": "cte.tasks.plugin_lifecycle_task.execute_plugin"},
    {"$set": {"task": "cte.execute_plugin"}},
)

print("Successfully migrated database to version 1.3.0")
