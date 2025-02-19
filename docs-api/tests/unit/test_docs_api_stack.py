import aws_cdk as core
import aws_cdk.assertions as assertions

from docs_api.docs_api_stack import DocsApiStack

# example tests. To run these tests, uncomment this file along with the example
# resource in docs_api/docs_api_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = DocsApiStack(app, "docs-api")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
