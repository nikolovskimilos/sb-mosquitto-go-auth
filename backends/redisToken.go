package backends

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/iegomez/mosquitto-go-auth/common"

	goredis "github.com/go-redis/redis"
)

type RedisToken struct {
	Host     string
	Port     string
	Password string
	DB       int32
	Conn     *goredis.Client
}

func NewRedisToken(authOpts map[string]string, logLevel log.Level) (RedisToken, error) {

	log.SetLevel(logLevel)

	var redis = RedisToken{
		Host: "localhost",
		Port: "6379",
		DB:   1,
	}

	if redisHost, ok := authOpts["redis_token_host"]; ok {
		redis.Host = redisHost
	}

	if redisPort, ok := authOpts["redis_token_port"]; ok {
		redis.Port = redisPort
	}

	if redisPassword, ok := authOpts["redis_token_password"]; ok {
		redis.Password = redisPassword
	}

	if redisDB, ok := authOpts["redis_token_db"]; ok {
		db, err := strconv.ParseInt(redisDB, 10, 32)
		if err == nil {
			redis.DB = int32(db)
		}
	}

	addr := fmt.Sprintf("%s:%s", redis.Host, redis.Port)

	//Try to start redis.
	goredisClient := goredis.NewClient(&goredis.Options{
		Addr:     addr,
		Password: redis.Password,
		DB:       int(redis.DB),
	})

	for {
		if _, err := goredisClient.Ping().Result(); err != nil {
			log.Errorf("ping redis error, will retry in 2s: %s", err)
			time.Sleep(2 * time.Second)
		} else {
			break
		}
	}

	redis.Conn = goredisClient

	return redis, nil

}

//GetUser checks that the id exists and the given token is valid.
func (o RedisToken) GetUser(id, token, clientid string) bool {

	redisToken, err := o.Conn.Get(id).Result()

	if err != nil {
		log.Debugf("Redis get user error: %s", err)
		return false
	}

	return redisToken == token
}

//GetSuperuser checks that the key {id}:su exists and has value "true".
func (o RedisToken) GetSuperuser(id string) bool {

	isSuper, err := o.Conn.Get(fmt.Sprintf("%s:su", id)).Result()

	if err != nil {
		log.Debugf("Redis get superuser error: %s", err)
		return false
	}

	return isSuper == "true"
}

//CheckAcl gets all acls for the id and tries to match against topic, acc, and id/clientid if needed.
func (o RedisToken) CheckAcl(id, topic, clientid string, acc int32) bool {

	var acls []string       //User specific acls.
	var commonAcls []string //Common acls.

	//We need to check if client is subscribing, reading or publishing to get correct acls.
	switch acc {
	case MOSQ_ACL_SUBSCRIBE:
		//Get all user subscribe acls.
		var err error
		acls, err = o.Conn.SMembers(fmt.Sprintf("%s:sacls", id)).Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

		//Get common subscribe acls.
		commonAcls, err = o.Conn.SMembers("common:sacls").Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

	case MOSQ_ACL_READ:
		//Get all user read and readwrite acls.
		urAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:racls", id)).Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}
		urwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:rwacls", id)).Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

		//Get common read and readwrite acls
		rAcls, err := o.Conn.SMembers("common:racls").Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}
		rwAcls, err := o.Conn.SMembers("common:rwacls").Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

		acls = make([]string, len(urAcls)+len(urwAcls))
		acls = append(acls, urAcls...)
		acls = append(acls, urwAcls...)

		commonAcls = make([]string, len(rAcls)+len(rwAcls))
		commonAcls = append(commonAcls, rAcls...)
		commonAcls = append(commonAcls, rwAcls...)
	case MOSQ_ACL_WRITE:
		//Get all user write and readwrite acls.
		uwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:wacls", id)).Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}
		urwAcls, err := o.Conn.SMembers(fmt.Sprintf("%s:rwacls", id)).Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

		//Get common write and readwrite acls
		wAcls, err := o.Conn.SMembers("common:wacls").Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}
		rwAcls, err := o.Conn.SMembers("common:rwacls").Result()
		if err != nil {
			log.Debugf("RedisToken check acl error: %s", err)
			return false
		}

		acls = make([]string, len(uwAcls)+len(urwAcls))
		acls = append(acls, uwAcls...)
		acls = append(acls, urwAcls...)

		commonAcls = make([]string, len(wAcls)+len(rwAcls))
		commonAcls = append(commonAcls, wAcls...)
		commonAcls = append(commonAcls, rwAcls...)
	}

	//Now loop through acls looking for a match.
	for _, acl := range acls {
		if common.TopicsMatch(acl, topic) {
			return true
		}
	}

	for _, acl := range commonAcls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", id, -1)
		if common.TopicsMatch(aclTopic, topic) {
			return true
		}
	}

	return false

}

//GetName returns the backend's name
func (o RedisToken) GetName() string {
	return "RedisToken"
}

//Halt terminates the connection.
func (o RedisToken) Halt() {
	if o.Conn != nil {
		err := o.Conn.Close()
		if err != nil {
			log.Errorf("Redis cleanup error: %s", err)
		}
	}
}
