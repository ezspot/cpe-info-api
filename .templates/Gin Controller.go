package ${GO_PACKAGE_NAME}

func New${ENTITY_NAME}Controller() *${ENTITY_NAME}Controller {
    return &${ENTITY_NAME}Controller{}
}

type ${ENTITY_NAME}Controller struct {
}

// Get is a gin handler function.
// TODO
// @Summary ADD A BRIEF SUMMARY 
// @Tags ADD A TAG
// @Accept json
// @Produce json
// @Success 200 {object} models.Entity "DESCRIPTION"
// @Router /route/to/endpoint [get]
func (controller *${ENTITY_NAME}Controller) Get(c *gin.Context) {

}