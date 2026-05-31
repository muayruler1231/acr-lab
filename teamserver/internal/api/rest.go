package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/muayruler1231/acr-lab/teamserver/internal/core"
)

func ServeREST(addr string, scheduler *core.Scheduler) error {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// TODO: operator auth middleware (mTLS or API key)

	agents := r.Group("/api/v1/agents")
	{
		agents.GET("", listAgents(scheduler))
		agents.POST("/:id/task", issueTask(scheduler))
	}

	profiles := r.Group("/api/v1/profiles")
	{
		profiles.GET("/active", getActiveProfile(scheduler))
		profiles.POST("", loadProfile(scheduler))
	}

	return r.Run(addr)
}

func listAgents(s *core.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: query store, stream JSON
		c.JSON(http.StatusOK, gin.H{"agents": []interface{}{}})
	}
}

func issueTask(s *core.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: bind JSON body to store.Task, call scheduler.IssueTask
		c.JSON(http.StatusAccepted, gin.H{"status": "queued"})
	}
}

func getActiveProfile(s *core.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: return active 3-plane profile JSON
		c.JSON(http.StatusOK, gin.H{})
	}
}

func loadProfile(s *core.Scheduler) gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: read multipart or JSON body, validate, apply
		c.JSON(http.StatusOK, gin.H{"status": "loaded"})
	}
}
