package backends

import (
	"testing"

	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func TestRedisToken(t *testing.T) {

	//Initialize Redis with some test values.
	authOpts := make(map[string]string)
	authOpts["redis_host"] = "localhost"
	authOpts["redis_port"] = "6379"
	authOpts["redis_db"] = "2"
	authOpts["redis_password"] = ""

	Convey("Given valid params NewRedis should return a Redis backend instance", t, func() {
		redis, err := NewRedis(authOpts, log.DebugLevel)
		So(err, ShouldBeNil)

		//Empty db
		redis.Conn.FlushDB()

		//Insert a user to test auth
		id := "id:q3n4j4q59w4857w0498y4rq4wyr"
		token := "23h49583hy43098r2h4098h3p2huqrp89ry4pwr8owhap840y98qryw4098ay09"

		redis.Conn.Set(id, token, 0)

		Convey("Given an id and a correct password, it should correctly authenticate it", func() {

			authenticated := redis.GetUser(id, token, "")
			So(authenticated, ShouldBeTrue)
		})

		Convey("Given an id and an incorrect password, it should not authenticate it", func() {

			authenticated := redis.GetUser(id, "wrong_password", "")
			So(authenticated, ShouldBeFalse)
		})

		redis.Conn.Set(id+":su", "true", 0)
		Convey("Given an id that is superuser, super user check should pass", func() {
			superuser := redis.GetSuperuser(id)
			So(superuser, ShouldBeTrue)
		})

		//Now create some acls and test topics

		strictAcl := id + "/topic/1"
		singleLevelAcl := id + "/topic/+"
		hierarchyAcl := id + "/#"

		userPattern := id + "/%u"
		clientPattern := id + "/%c"

		clientID := "test_client"

		writeAcl := "write/test"

		readWriteAcl := id + "/readwrite/1"

		commonTopic := "common/test/topic"

		redis.Conn.SAdd(id+":racls", strictAcl)

		Convey("Given only strict acl in DB, an exact match should work and and inexact one not", func() {

			testTopic1 := id + `/topic/1`
			testTopic2 := id + `/topic/2`

			tt1 := redis.CheckAcl(id, testTopic1, clientID, MOSQ_ACL_READ)
			tt2 := redis.CheckAcl(id, testTopic2, clientID, MOSQ_ACL_READ)

			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeFalse)

		})

		Convey("Given wildcard subscriptions against strict db acl, acl checks should fail", func() {

			tt1 := redis.CheckAcl(id, singleLevelAcl, clientID, MOSQ_ACL_READ)
			tt2 := redis.CheckAcl(id, hierarchyAcl, clientID, MOSQ_ACL_READ)

			So(tt1, ShouldBeFalse)
			So(tt2, ShouldBeFalse)

		})

		//Now check against common patterns.
		redis.Conn.SAdd("common:racls", userPattern)

		Convey("Given a topic that mentions id and subscribes to it, acl check should pass", func() {
			tt1 := redis.CheckAcl(id, id+"/test", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		redis.Conn.SAdd("common:racls", clientPattern)

		Convey("Given a topic that mentions clientid, acl check should pass", func() {
			tt1 := redis.CheckAcl(id, "test/test_client", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		//Now insert single level topic to check against.

		redis.Conn.SAdd(id+":racls", singleLevelAcl)

		Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
			tt1 := redis.CheckAcl(id, "test/topic/whatever", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		//Now insert hierarchy wildcard to check against.

		redis.Conn.SAdd(id+":racls", hierarchyAcl)

		Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
			tt1 := redis.CheckAcl(id, "test/what/ever", clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		//Now test against a publish subscription
		Convey("Given a publish attempt for a read only acl, acl check should fail", func() {
			tt1 := redis.CheckAcl(id, "test/test", clientID, MOSQ_ACL_WRITE)
			So(tt1, ShouldBeFalse)
		})

		//Add a write only acl and check for subscription.
		redis.Conn.SAdd(id+":wacls", writeAcl)
		Convey("Given a subscription attempt on a write only acl, acl check should fail", func() {
			tt1 := redis.CheckAcl(id, writeAcl, clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeFalse)
		})

		//Add a readwrite acl and check for subscription.
		redis.Conn.SAdd(id+":rwacls", readWriteAcl)
		Convey("Given a sub/pub attempt on a readwrite acl, acl check should pass for both", func() {
			tt1 := redis.CheckAcl(id, readWriteAcl, clientID, MOSQ_ACL_READ)
			tt2 := redis.CheckAcl(id, readWriteAcl, clientID, MOSQ_ACL_WRITE)
			So(tt1, ShouldBeTrue)
			So(tt2, ShouldBeTrue)
		})

		//Now common acl to check against.
		redis.Conn.SAdd("common:racls", commonTopic)

		Convey("Given a topic not present in user's acls but present in common ones, acl check should pass", func() {
			tt1 := redis.CheckAcl("unknown", commonTopic, clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeTrue)
		})

		Convey("Given a topic thay may be read but not subscribed to, checking for subscribe should failbut read shoud succeed", func() {
			topic := "some/topic"
			redis.Conn.SAdd(id+":racls", topic)
			tt1 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_SUBSCRIBE)
			tt2 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_READ)
			So(tt1, ShouldBeFalse)
			So(tt2, ShouldBeTrue)
			Convey("When adding subscribe permissions, both should be accepted", func() {
				redis.Conn.SAdd(id+":sacls", topic)
				tt1 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_SUBSCRIBE)
				tt2 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeTrue)
			})
			Convey("When adding it as a common subscribe acl, both should be accepted", func() {
				redis.Conn.SAdd("common:sacls", topic)
				tt1 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_SUBSCRIBE)
				tt2 := redis.CheckAcl(id, topic, clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeTrue)
			})
		})

		//Empty db
		redis.Conn.FlushDB()

		redis.Halt()

	})

}
